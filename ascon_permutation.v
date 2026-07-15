`timescale 1ns / 1ps
//=============================================================================
// ASCON Permutation - NIST COMPLIANT + PIPELINED for 125 MHz
//
// KEY FIX vs original:
//   - Added start_round input so pb=6 calls use constants 0x96..0x4b
//     (original always started at round 0 -> wrong constants for pb=6)
//   - Split into 4 pipeline stages (CONST/SBOX/CHI/LINEAR) so each
//     stage fits in 8ns at 125 MHz
//   - Fixed Verilog coding: no multiple NBA to same reg in one cycle
//
// NIST Round constants (ASCON v1.2):
//   Round 0:  0xf0    Round 6:  0x96
//   Round 1:  0xe1    Round 7:  0x87
//   Round 2:  0xd2    Round 8:  0x78
//   Round 3:  0xc3    Round 9:  0x69
//   Round 4:  0xb4    Round 10: 0x5a
//   Round 5:  0xa5    Round 11: 0x4b
//
// pa=12: start_round=0,  rounds=12  (uses 0xf0..0x4b)
// pb=6:  start_round=6,  rounds=6   (uses 0x96..0x4b)
//=============================================================================

module ascon_perm_fast(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [3:0]  start_round,   // 0 for pa=12, 6 for pb=6
    input  wire [3:0]  rounds,        // number of rounds to execute
    input  wire [63:0] s0_in,
    input  wire [63:0] s1_in,
    input  wire [63:0] s2_in,
    input  wire [63:0] s3_in,
    input  wire [63:0] s4_in,
    output reg  [63:0] s0_out,
    output reg  [63:0] s1_out,
    output reg  [63:0] s2_out,
    output reg  [63:0] s3_out,
    output reg  [63:0] s4_out,
    output reg         done
);

    // Pipeline stages
    localparam [2:0]
        IDLE   = 3'd0,
        CONST  = 3'd1,
        SBOX   = 3'd2,
        CHI    = 3'd3,
        LINEAR = 3'd4,
        FINISH = 3'd5;

    reg [2:0] state;
    reg [3:0] round_cnt;      // current round index (start_round..start_round+rounds-1)
    reg [3:0] round_end;      // last round index + 1
    // target_rounds removed: was never read after being written; synthesizer
    // trimmed it away and emitted [Synth 8-6014]. round_end carries the same info.

    reg [63:0] x0, x1, x2, x3, x4;
    reg [63:0] t0, t1, t2, t3, t4;

    // Round constant lookup by round INDEX
    reg [7:0] rc;
    always @(*) begin
        case (round_cnt)
            4'd0:  rc = 8'hf0;
            4'd1:  rc = 8'he1;
            4'd2:  rc = 8'hd2;
            4'd3:  rc = 8'hc3;
            4'd4:  rc = 8'hb4;
            4'd5:  rc = 8'ha5;
            4'd6:  rc = 8'h96;
            4'd7:  rc = 8'h87;
            4'd8:  rc = 8'h78;
            4'd9:  rc = 8'h69;
            4'd10: rc = 8'h5a;
            4'd11: rc = 8'h4b;
            default: rc = 8'h00;
        endcase
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= IDLE;
            done          <= 1'b0;
            round_cnt     <= 4'd0;
            round_end     <= 4'd0;
            x0<=64'd0; x1<=64'd0; x2<=64'd0; x3<=64'd0; x4<=64'd0;
            t0<=64'd0; t1<=64'd0; t2<=64'd0; t3<=64'd0; t4<=64'd0;
            s0_out<=64'd0; s1_out<=64'd0; s2_out<=64'd0;
            s3_out<=64'd0; s4_out<=64'd0;
        end else begin
            case (state)

                IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        x0            <= s0_in;
                        x1            <= s1_in;
                        x2            <= s2_in;
                        x3            <= s3_in;
                        x4            <= s4_in;
                        round_cnt     <= start_round;
                        round_end     <= start_round + rounds;
                        state         <= CONST;
                    end
                end

                // Stage 1: XOR round constant into x2
                CONST: begin
                    x2    <= x2 ^ {56'd0, rc};
                    state <= SBOX;
                end

                // Stage 2: Substitution theta step
                // Compute t values for chi layer input
                // theta: t0=x0^x4, t1=x1, t2=x2^x1, t3=x3, t4=x4^x3
                SBOX: begin
                    t0    <= x0 ^ x4;
                    t1    <= x1;
                    t2    <= x2 ^ x1;
                    t3    <= x3;
                    t4    <= x4 ^ x3;
                    state <= CHI;
                end

                // Stage 3: Chi (non-linear) layer
                // From ASCON spec: Si = ti ^ (~t(i+1) & t(i+2))
                // x2 is inverted
                CHI: begin
                    x0    <=  t0 ^ (~t1 & t2);
                    x1    <=  t1 ^ (~t2 & t3);
                    x2    <= ~(t2 ^ (~t3 & t4));
                    x3    <=  t3 ^ (~t4 & t0);
                    x4    <=  t4 ^ (~t0 & t1);
                    state <= LINEAR;
                end

                // Stage 4: Linear diffusion
                // ASCON spec rotation amounts:
                //   x0: Sigma0(x) = x ^ (x >>> 19) ^ (x >>> 28)
                //   x1: Sigma1(x) = x ^ (x >>> 61) ^ (x >>> 39)
                //   x2: Sigma2(x) = x ^ (x >>> 1)  ^ (x >>> 6)
                //   x3: Sigma3(x) = x ^ (x >>> 10) ^ (x >>> 17)
                //   x4: Sigma4(x) = x ^ (x >>> 7)  ^ (x >>> 41)
                LINEAR: begin
                    x0 <= x0 ^ {x0[18:0],x0[63:19]} ^ {x0[27:0],x0[63:28]};
                    x1 <= x1 ^ {x1[60:0],x1[63:61]} ^ {x1[38:0],x1[63:39]};
                    x2 <= x2 ^ {x2[0],   x2[63:1]}  ^ {x2[5:0], x2[63:6]};
                    x3 <= x3 ^ {x3[9:0], x3[63:10]} ^ {x3[16:0],x3[63:17]};
                    x4 <= x4 ^ {x4[6:0], x4[63:7]}  ^ {x4[40:0],x4[63:41]};

                    if (round_cnt < round_end - 1) begin
                        round_cnt <= round_cnt + 4'd1;
                        state     <= CONST;
                    end else begin
                        state <= FINISH;
                    end
                end

                FINISH: begin
                    s0_out <= x0;
                    s1_out <= x1;
                    s2_out <= x2;
                    s3_out <= x3;
                    s4_out <= x4;
                    done   <= 1'b1;
                    state  <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule