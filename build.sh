#!/usr/bin/env bash
# =====================================================================
# Hefestos SIGINT v5.1.0 - build de todos os nos
#
# Requisitos:
#   - arduino-cli >= 0.35
#   - core esp32:esp32 EXATAMENTE 2.0.17 (mbedtls 2.x)
#   - bibliotecas externas (ver dependencias.txt)
#
# A biblioteca compartilhada deste repositorio (lib/) e' passada via
# --libraries, o que resolve o include quebrado da v4 ("../lib/...").
# =====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="${ARDUINO_CLI:-arduino-cli}"
CORE_VERSION="2.0.17"
BUILD_DIR="$ROOT/build"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERRO: arduino-cli nao encontrado no PATH." >&2
    echo "      Instale em https://arduino.github.io/arduino-cli/ e reexecute." >&2
    exit 1
fi

INSTALLED="$("$CLI" core list 2>/dev/null | awk '$1=="esp32:esp32"{print $2}')"
if [ "$INSTALLED" != "$CORE_VERSION" ]; then
    echo "ERRO: core esp32 instalado='${INSTALLED:-nenhum}', exigido='$CORE_VERSION'." >&2
    echo "      Execute: $CLI core install esp32:esp32@$CORE_VERSION" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

compile_node() {
    local name="$1"
    local fqbn="$2"
    local sketch="$3"

    echo
    echo "==> Compilando $name ($fqbn)"
    "$CLI" compile \
        --fqbn "$fqbn" \
        --libraries "$ROOT" \
        --build-path "$BUILD_DIR/$name" \
        --warnings default \
        "$sketch"
}

compile_node "node1" "esp32:esp32:esp32"   "$ROOT/src/Node1_Transmissor_Alvo"
compile_node "node2" "esp32:esp32:esp32"   "$ROOT/src/Node2_Base_Hefestos"
compile_node "node3" "esp32:esp32:esp32c3" "$ROOT/src/Node3_Caixa_Preta_ESP32C3"

echo
echo "====================================================="
echo " BUILD OK - Hefestos SIGINT v5.1.0 (3/3 nos)"
echo " Artefatos em: $BUILD_DIR"
echo "====================================================="
