`timescale 1ns / 1ps
//=============================================================================
// UART Receiver - 115200 baud, 8N1
// CLK_FREQ / BAUD_RATE = 25_000_000 / 115200 = ~217 clocks/bit
//=============================================================================
module uart_rx #(
    parameter CLK_FREQ  = 100_000_000,
    parameter BAUD_RATE = 115_200
)(
    input  wire       clk,
    input  wire       rst_n,
    input  wire       rx,          // Serial input (from UART pin)
    output reg  [7:0] data,        // Received byte
    output reg        data_valid   // Pulses one cycle when byte ready
);
    localparam integer CLKS_PER_BIT = CLK_FREQ / BAUD_RATE;  // 217
    localparam integer HALF_BIT     = CLKS_PER_BIT / 2;      // 108

    localparam [1:0] IDLE  = 2'd0,
                     START = 2'd1,
                     DATA  = 2'd2,
                     STOP  = 2'd3;

    reg [1:0]  state;
    reg [15:0] clk_cnt;
    reg [2:0]  bit_idx;
    reg [7:0]  rx_shift;
    reg        rx_sync1, rx_sync2;  // 2-FF synchronizer for metastability

    // Synchronize async UART input to system clock domain
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_sync1 <= 1'b1;
            rx_sync2 <= 1'b1;
        end else begin
            rx_sync1 <= rx;
            rx_sync2 <= rx_sync1;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= IDLE;
            clk_cnt    <= 16'd0;
            bit_idx    <= 3'd0;
            rx_shift   <= 8'd0;
            data       <= 8'd0;
            data_valid <= 1'b0;
        end else begin
            data_valid <= 1'b0;  // Default: not valid
            case (state)
                IDLE: begin
                    clk_cnt <= 16'd0;
                    bit_idx <= 3'd0;
                    if (rx_sync2 == 1'b0) begin
                        // Detected start bit (line low)
                        state <= START;
                    end
                end

                START: begin
                    // Wait half a bit period to sample in the middle of start bit
                    if (clk_cnt == HALF_BIT - 1) begin
                        clk_cnt <= 16'd0;
                        if (rx_sync2 == 1'b0) begin
                            // Valid start bit
                            state <= DATA;
                        end else begin
                            // Noise - return to idle
                            state <= IDLE;
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end
                end

                DATA: begin
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt              <= 16'd0;
                        rx_shift[bit_idx]    <= rx_sync2;
                        if (bit_idx == 3'd7) begin
                            bit_idx <= 3'd0;
                            state   <= STOP;
                        end else begin
                            bit_idx <= bit_idx + 3'd1;
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end
                end

                STOP: begin
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        data       <= rx_shift;
                        data_valid <= 1'b1;
                        state      <= IDLE;
                        clk_cnt    <= 16'd0;
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end 
                end

                // No default needed: 2-bit state covers all 4 cases above
            endcase
        end
    end
endmodule