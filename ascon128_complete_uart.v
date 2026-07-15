`timescale 1ns / 1ps
//=============================================================================
// ASCON-128 Complete Implementation - Variable-Length Plaintext Edition
//
// Supports 1..N_MAX_BLOCKS*8 bytes of plaintext (default = 8 blocks = 64 B).
// pt_len_bytes [6:0]: actual byte count before padding; core computes
// num_blocks_lat = ceil(pt_len_bytes/8) on start and iterates exactly that
// many 64-bit rate blocks.
//
// dec_tag_override: skip encrypt, run decrypt directly.
//   pt_padded carries the ciphertext; dec_tag_in carries the expected tag.
//
// FIX [TM]: tag_match was cleared to 0 in ST_IDLE (one cycle after ST_DONE),
//   so any FSM sampling it after the done pulse saw 0 ("Verify: NO").
//   tag_match is now a sticky register: it is set in ST_DEC_FINAL_W and held
//   until the next ST_IDLE->start transition resets it.  done is still a
//   one-cycle pulse so callers must latch it.
//
// SYNTHESIS RULES FOLLOWED:
//   - No variable-base part-selects on runtime signals.
//   - All wide-bus <-> array conversions use generate/assign (constant indices).
//   - integer loop vars only inside clocked always resets (Vivado-safe).
//   - No multiple drivers on any signal.
//   - ciphertext/plaintext_dec are wire outputs reassembled from registered arrays.
//=============================================================================

module ascon128_complete_uart #(
    parameter N_MAX_BLOCKS = 8   // max 64-bit rate blocks = max 64 bytes PT
)(
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,

    input  wire [127:0] key,
    input  wire [127:0] nonce,
    input  wire [63:0]  aad_padded,
    input  wire [N_MAX_BLOCKS*64-1:0] pt_padded,
    input  wire [6:0]   pt_len_bytes,   // actual bytes before padding

    input  wire         dec_tag_override,
    input  wire [127:0] dec_tag_in,

    output wire [N_MAX_BLOCKS*64-1:0] ciphertext,    // wire, driven by ct_blk[]
    output reg  [127:0] tag_out,
    output wire [N_MAX_BLOCKS*64-1:0] plaintext_dec, // wire, driven by ptd_blk[]
    output reg          done,
    output reg          tag_match,   // sticky: set at decrypt done, cleared on next start
    output reg          session_done
);

    localparam [63:0] IV = 64'h80400c0600000000;

    localparam [4:0]
        ST_IDLE          = 5'd0,  ST_ENC_INIT      = 5'd1,  ST_ENC_INIT_PERM = 5'd2,
        ST_ENC_AAD       = 5'd3,  ST_ENC_AAD_PERM  = 5'd4,  ST_ENC_AAD_DOM   = 5'd5,
        ST_ENC_PT        = 5'd6,  ST_ENC_PT_PERM   = 5'd7,  ST_ENC_FINAL     = 5'd8,
        ST_ENC_FINAL_W   = 5'd9,  ST_TAG_STORE     = 5'd10, ST_DEC_INIT      = 5'd11,
        ST_DEC_INIT_PERM = 5'd12, ST_DEC_AAD       = 5'd13, ST_DEC_AAD_PERM  = 5'd14,
        ST_DEC_AAD_DOM   = 5'd15, ST_DEC_CT        = 5'd16, ST_DEC_CT_PERM   = 5'd17,
        ST_DEC_FINAL     = 5'd18, ST_DEC_FINAL_W   = 5'd19, ST_DONE          = 5'd20;

    reg [4:0]   state;
    reg [63:0]  s0, s1, s2, s3, s4;
    reg [127:0] tag_enc;
    reg [3:0]   block_idx;
    reg [3:0]   num_blocks_lat;

    reg [127:0] key_lat, nonce_lat;
    reg [63:0]  aad_lat;
    reg [N_MAX_BLOCKS*64-1:0] pt_lat;
    reg         dec_override_lat;
    reg [127:0] dec_tag_lat;

    //=========================================================================
    // BLOCK ARRAYS  (registered, indexed by block_idx at runtime - legal)
    // pt_blk[] : combinationally unpacked from pt_lat via generate/assign
    // ct_blk[] : written by FSM, reassembled to ciphertext via generate/assign
    // ptd_blk[]: written by FSM, reassembled to plaintext_dec via generate/assign
    //=========================================================================
    wire [63:0] pt_blk  [0:N_MAX_BLOCKS-1];
    reg  [63:0] ct_blk  [0:N_MAX_BLOCKS-1];
    reg  [63:0] ptd_blk [0:N_MAX_BLOCKS-1];

    // Unpack pt_lat into pt_blk[] - all indices are constants after elaboration
    genvar gi;
    generate
        for (gi = 0; gi < N_MAX_BLOCKS; gi = gi + 1) begin : gen_pt_unpack
            assign pt_blk[gi] = pt_lat[(N_MAX_BLOCKS-1-gi)*64 +: 64];
        end
    endgenerate

    // Pack ct_blk[] -> ciphertext output wire
    generate
        for (gi = 0; gi < N_MAX_BLOCKS; gi = gi + 1) begin : gen_ct_pack
            assign ciphertext[(N_MAX_BLOCKS-1-gi)*64 +: 64] = ct_blk[gi];
        end
    endgenerate

    // Pack ptd_blk[] -> plaintext_dec output wire
    generate
        for (gi = 0; gi < N_MAX_BLOCKS; gi = gi + 1) begin : gen_ptd_pack
            assign plaintext_dec[(N_MAX_BLOCKS-1-gi)*64 +: 64] = ptd_blk[gi];
        end
    endgenerate

    //=========================================================================
    // ceil(n/8): purely combinational, n is runtime - result is registered
    // into num_blocks_lat on start, so it only needs to be correct for one cycle.
    //=========================================================================
    function [3:0] ceil_div8;
        input [6:0] n;   // FIX: was [5:0] - pt_len_bytes is 7-bit, truncation caused num_blocks=0
        reg [7:0] t;
        begin
            if (n == 7'd0) begin
                ceil_div8 = 4'd1;
            end else begin
                t = {1'b0, n} + 8'd7;
                ceil_div8 = t[6:3];
                if (ceil_div8 > N_MAX_BLOCKS[3:0])
                    ceil_div8 = N_MAX_BLOCKS[3:0];
            end
        end
    endfunction

    //=========================================================================
    // PERMUTATION INTERFACE
    //=========================================================================
    reg         perm_start;
    wire        perm_done;
    reg  [3:0]  perm_start_round;
    reg  [3:0]  perm_num_rounds;
    wire [63:0] perm_out0, perm_out1, perm_out2, perm_out3, perm_out4;

    ascon_perm_fast perm_inst (
        .clk(clk), .rst_n(rst_n), .start(perm_start),
        .start_round(perm_start_round), .rounds(perm_num_rounds),
        .s0_in(s0), .s1_in(s1), .s2_in(s2), .s3_in(s3), .s4_in(s4),
        .s0_out(perm_out0), .s1_out(perm_out1), .s2_out(perm_out2),
        .s3_out(perm_out3), .s4_out(perm_out4), .done(perm_done)
    );

    //=========================================================================
    // MAIN FSM
    //=========================================================================
    integer ri;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= ST_IDLE;
            done             <= 1'b0;
            tag_match        <= 1'b0;
            session_done     <= 1'b0;
            perm_start       <= 1'b0;
            perm_start_round <= 4'd0;
            perm_num_rounds  <= 4'd0;
            block_idx        <= 4'd0;
            num_blocks_lat   <= 4'd1;
            s0<=64'd0; s1<=64'd0; s2<=64'd0; s3<=64'd0; s4<=64'd0;
            tag_enc          <= 128'd0;
            tag_out          <= 128'd0;
            key_lat          <= 128'd0;
            nonce_lat        <= 128'd0;
            aad_lat          <= 64'd0;
            pt_lat           <= {N_MAX_BLOCKS*64{1'b0}};
            dec_override_lat <= 1'b0;
            dec_tag_lat      <= 128'd0;
            for (ri = 0; ri < N_MAX_BLOCKS; ri = ri + 1) begin
                ct_blk[ri]  <= 64'd0;
                ptd_blk[ri] <= 64'd0;
            end
        end else begin
            perm_start   <= 1'b0;
            session_done <= 1'b0;

            case (state)

                ST_IDLE: begin
                    done <= 1'b0;
                    // [FIX-TM] Do NOT clear tag_match here - it is sticky so
                    // the UART FSM can read it any number of cycles after done.
                    // It is cleared at the start of the next operation below.
                    if (start) begin
                        tag_match        <= 1'b0;   // clear for new operation
                        key_lat          <= key;
                        nonce_lat        <= nonce;
                        aad_lat          <= aad_padded;
                        pt_lat           <= pt_padded;
                        dec_override_lat <= dec_tag_override;
                        dec_tag_lat      <= dec_tag_in;
                        num_blocks_lat   <= ceil_div8(pt_len_bytes);
                        state <= dec_tag_override ? ST_DEC_INIT : ST_ENC_INIT;
                    end
                end

                // ── ENCRYPT ─────────────────────────────────────────────────
                ST_ENC_INIT: begin
                    s0 <= IV;
                    s1 <= key_lat[127:64];
                    s2 <= key_lat[63:0];
                    s3 <= nonce_lat[127:64];
                    s4 <= nonce_lat[63:0];
                    perm_start_round <= 4'd0;
                    perm_num_rounds  <= 4'd12;
                    perm_start <= 1'b1;
                    state      <= ST_ENC_INIT_PERM;
                end

                ST_ENC_INIT_PERM: begin
                    if (perm_done) begin
                        s0    <= perm_out0;
                        s1    <= perm_out1;
                        s2    <= perm_out2;
                        s3    <= perm_out3 ^ key_lat[127:64];
                        s4    <= perm_out4 ^ key_lat[63:0];
                        state <= ST_ENC_AAD;
                    end
                end

                ST_ENC_AAD: begin
                    s0 <= s0 ^ aad_lat;
                    perm_start_round <= 4'd6;
                    perm_num_rounds  <= 4'd6;
                    perm_start <= 1'b1;
                    state      <= ST_ENC_AAD_PERM;
                end

                ST_ENC_AAD_PERM: begin
                    if (perm_done) begin
                        s0 <= perm_out0; s1 <= perm_out1; s2 <= perm_out2;
                        s3 <= perm_out3; s4 <= perm_out4;
                        state <= ST_ENC_AAD_DOM;
                    end
                end

                ST_ENC_AAD_DOM: begin
                    s4        <= s4 ^ 64'h0000000000000001;
                    block_idx <= 4'd0;
                    state     <= ST_ENC_PT;
                end

                ST_ENC_PT: begin
                    if (block_idx < num_blocks_lat) begin
                        ct_blk[block_idx] <= s0 ^ pt_blk[block_idx];
                        s0                <= s0 ^ pt_blk[block_idx];
                        if (block_idx < num_blocks_lat - 4'd1) begin
                            perm_start_round <= 4'd6;
                            perm_num_rounds  <= 4'd6;
                            perm_start       <= 1'b1;
                            block_idx        <= block_idx + 4'd1;
                            state            <= ST_ENC_PT_PERM;
                        end else begin
                            state <= ST_ENC_FINAL;
                        end
                    end else begin
                        state <= ST_ENC_FINAL;
                    end
                end

                ST_ENC_PT_PERM: begin
                    if (perm_done) begin
                        s0 <= perm_out0; s1 <= perm_out1; s2 <= perm_out2;
                        s3 <= perm_out3; s4 <= perm_out4;
                        state <= ST_ENC_PT;
                    end
                end

                ST_ENC_FINAL: begin
                    s1 <= s1 ^ key_lat[127:64];
                    s2 <= s2 ^ key_lat[63:0];
                    perm_start_round <= 4'd0;
                    perm_num_rounds  <= 4'd12;
                    perm_start <= 1'b1;
                    state      <= ST_ENC_FINAL_W;
                end

                ST_ENC_FINAL_W: begin
                    if (perm_done) begin
                        tag_enc <= {perm_out3 ^ key_lat[127:64], perm_out4 ^ key_lat[63:0]};
                        tag_out <= {perm_out3 ^ key_lat[127:64], perm_out4 ^ key_lat[63:0]};
                        state   <= ST_TAG_STORE;
                    end
                end

                ST_TAG_STORE: state <= dec_override_lat ? ST_DEC_INIT : ST_DONE;

                // ── DECRYPT ─────────────────────────────────────────────────
                ST_DEC_INIT: begin
                    s0 <= IV;
                    s1 <= key_lat[127:64];
                    s2 <= key_lat[63:0];
                    s3 <= nonce_lat[127:64];
                    s4 <= nonce_lat[63:0];
                    perm_start_round <= 4'd0;
                    perm_num_rounds  <= 4'd12;
                    perm_start <= 1'b1;
                    state      <= ST_DEC_INIT_PERM;
                end

                ST_DEC_INIT_PERM: begin
                    if (perm_done) begin
                        s0    <= perm_out0;
                        s1    <= perm_out1;
                        s2    <= perm_out2;
                        s3    <= perm_out3 ^ key_lat[127:64];
                        s4    <= perm_out4 ^ key_lat[63:0];
                        state <= ST_DEC_AAD;
                    end
                end

                ST_DEC_AAD: begin
                    s0 <= s0 ^ aad_lat;
                    perm_start_round <= 4'd6;
                    perm_num_rounds  <= 4'd6;
                    perm_start <= 1'b1;
                    state      <= ST_DEC_AAD_PERM;
                end

                ST_DEC_AAD_PERM: begin
                    if (perm_done) begin
                        s0 <= perm_out0; s1 <= perm_out1; s2 <= perm_out2;
                        s3 <= perm_out3; s4 <= perm_out4;
                        state <= ST_DEC_AAD_DOM;
                    end
                end

                ST_DEC_AAD_DOM: begin
                    s4        <= s4 ^ 64'h0000000000000001;
                    block_idx <= 4'd0;
                    state     <= ST_DEC_CT;
                end

                ST_DEC_CT: begin
                    if (block_idx < num_blocks_lat) begin
                        ptd_blk[block_idx] <= s0 ^ (dec_override_lat ?
                                                     pt_blk[block_idx] :
                                                     ct_blk[block_idx]);
                        s0 <= dec_override_lat ? pt_blk[block_idx] : ct_blk[block_idx];
                        if (block_idx < num_blocks_lat - 4'd1) begin
                            perm_start_round <= 4'd6;
                            perm_num_rounds  <= 4'd6;
                            perm_start       <= 1'b1;
                            block_idx        <= block_idx + 4'd1;
                            state            <= ST_DEC_CT_PERM;
                        end else begin
                            state <= ST_DEC_FINAL;
                        end
                    end else begin
                        state <= ST_DEC_FINAL;
                    end
                end

                ST_DEC_CT_PERM: begin
                    if (perm_done) begin
                        s0 <= perm_out0; s1 <= perm_out1; s2 <= perm_out2;
                        s3 <= perm_out3; s4 <= perm_out4;
                        state <= ST_DEC_CT;
                    end
                end

                ST_DEC_FINAL: begin
                    s1 <= s1 ^ key_lat[127:64];
                    s2 <= s2 ^ key_lat[63:0];
                    perm_start_round <= 4'd0;
                    perm_num_rounds  <= 4'd12;
                    perm_start <= 1'b1;
                    state      <= ST_DEC_FINAL_W;
                end

                ST_DEC_FINAL_W: begin
                    if (perm_done) begin
                        // [FIX-TM] tag_match set here and held (not cleared in ST_IDLE)
                        tag_match    <= dec_override_lat ?
                            ({perm_out3^key_lat[127:64], perm_out4^key_lat[63:0]} == dec_tag_lat) :
                            (tag_enc == {perm_out3^key_lat[127:64], perm_out4^key_lat[63:0]});
                        state        <= ST_DONE;
                    end
                end

                ST_DONE: begin
                    // Assert done and session_done for exactly one cycle so callers
                    // can sample the results, then return to idle.
                    // tag_match remains held until next start (see ST_IDLE above).
                    done         <= 1'b1;
                    session_done <= 1'b1;
                    state        <= ST_IDLE;
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule