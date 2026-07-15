`timescale 1ns / 1ps
//=============================================================================
// UART Transmitter - 115200 baud, 8N1
//=============================================================================
module uart_tx #(
    parameter CLK_FREQ  = 100_000_000,
    parameter BAUD_RATE = 115_200
)(
    input  wire       clk,
    input  wire       rst_n,
    input  wire [7:0] data,        // Byte to transmit
    input  wire       send,        // Pulse to start transmission
    output reg        tx,          // Serial output
    output reg        busy         // High while transmitting
);
    localparam integer CLKS_PER_BIT = CLK_FREQ / BAUD_RATE;

    localparam [1:0] IDLE  = 2'd0,
                     START = 2'd1,
                     DATA  = 2'd2,
                     STOP  = 2'd3;

    reg [1:0]  state;
    reg [15:0] clk_cnt;
    reg [2:0]  bit_idx;
    reg [7:0]  tx_shift;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state   <= IDLE;
            tx      <= 1'b1;  // Idle high
            busy    <= 1'b0;
            clk_cnt <= 16'd0;
            bit_idx <= 3'd0;
            tx_shift<= 8'd0;
        end else begin
            case (state)
                IDLE: begin
                    tx   <= 1'b1;
                    busy <= 1'b0;
                    if (send) begin
                        tx_shift <= data;
                        busy     <= 1'b1;
                        state    <= START;
                        clk_cnt  <= 16'd0;
                    end
                end

                START: begin
                    tx <= 1'b0;  // Start bit
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= 16'd0;
                        bit_idx <= 3'd0;
                        state   <= DATA;
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end
                end

                DATA: begin
                    tx <= tx_shift[bit_idx];
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= 16'd0;
                        if (bit_idx == 3'd7) begin
                            state <= STOP;
                        end else begin
                            bit_idx <= bit_idx + 3'd1;
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end
                end

                STOP: begin
                    tx <= 1'b1;  // Stop bit
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= 16'd0;
                        state   <= IDLE;
                        busy    <= 1'b0;
                    end else begin
                        clk_cnt <= clk_cnt + 16'd1;
                    end
                end

                // No default needed: 2-bit state covers all 4 cases above
            endcase
        end
    end
endmodule