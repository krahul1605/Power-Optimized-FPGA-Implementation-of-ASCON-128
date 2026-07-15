A hardware/software implementation of the ASCON-128 authenticated encryption algorithm (NIST Lightweight Cryptography standard) on a Xilinx ZCU104 (Zynq UltraScale+) FPGA, interfaced with an ESP32 for real-time microphone audio capture, encryption, transmission, decryption, and playback. The project also includes a design-space exploration of 68+ RTL architecture variants of the ASCON permutation (pipelined, unrolled, bit-serial, TMR, near-threshold, clock-gated, etc.), evaluated and ranked using Power–Performance–Area (PPA) synthesis data with Boruta feature selection and TOPSIS multi-criteria decision analysis.

Overview

Core cipher: ASCON-128 permutation and authenticated encryption/decryption implemented in Verilog.
Target platform: Xilinx ZCU104 FPGA (Vivado project), with UART and SPI slave interfaces.
Edge node: ESP32 firmware (Arduino) that captures microphone audio (I2S), sends it to the FPGA over SPI for encryption/decryption, and plays back the recovered audio.
Design-space exploration: 68 hand-crafted RTL variants of the ASCON datapath (see variants/) targeting different power/area/throughput trade-offs, each with matching .sdc timing constraints.
Analysis pipeline: Python scripts that take post-synthesis PPA metrics for all variants and

run Boruta (Random Forest-based feature selection) to identify which physical metrics most influence power and area, and
run an 8-dimension TOPSIS ranking (power, area, latency, frequency, throughput, throughput/area, energy/bit, security) to identify the best-balanced architecture.
