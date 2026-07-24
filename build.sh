#!/bin/bash
set -euo pipefail

BOARD_ESP32="esp32:esp32:esp32"
BOARD_ESP32C3="esp32:esp32:esp32c3"
BUILD_DIR="build"

echo "=== HEFESTOS SIGINT v4.0 - Build ==="
echo ""

# === Node1 - Transmissor/Alvo (ESP32) ===
echo "--- Node1 (Transmissor/Alvo - ESP32) ---"
arduino-cli compile -b $BOARD_ESP32 \
  --build-path $BUILD_DIR/Node1 \
  --warnings all \
  src/Node1_Transmissor_Alvo/

echo ""

# === Node2 - Base Hefestos (ESP32) ===
echo "--- Node2 (Base Hefestos - ESP32) ---"
arduino-cli compile -b $BOARD_ESP32 \
  --build-path $BUILD_DIR/Node2 \
  --warnings all \
  src/Node2_Base_Hefestos/

echo ""

# === Node3 - Caixa Preta (ESP32-C3) ===
echo "--- Node3 (Caixa Preta - ESP32-C3) ---"
arduino-cli compile -b $BOARD_ESP32C3 \
  --build-path $BUILD_DIR/Node3 \
  --warnings all \
  src/Node3_Caixa_Preta_ESP32C3/

echo ""
echo "=== BUILD OK ==="