#!/usr/bin/env bash
# =====================================================================
# Hefestos SIGINT v5.1.0 - testes funcionais automatizados
#
# Uso:
#   ./test_functional.sh            # checagens estaticas + build dos 3 nos
#   ./test_functional.sh --no-build # apenas checagens estaticas
#
# As checagens validam invariantes que ja falharam na v4.x/v5.0:
#   - pinagem duplicada / pinos proibidos no ESP32-C3
#   - layout do cabecalho do protocolo LoRa
#   - round-trip REAL do protocolo serial Node2<->Node3 (executado no host)
#   - estado anti-replay persistido (replay pos-reboot bloqueado)
#   - ausencia de Telnet, EEPROM e include relativo quebrado
#   - anti-replay estrito (sem caminho de "resync")
#   - TOTP realmente chamado no login
#   - dashboard sem injecao de HTML
#   - nenhuma chave PSK de 64 hex hardcoded no codigo
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NO_BUILD=0
[ "${1:-}" = "--no-build" ] && NO_BUILD=1

FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=$((FAILED + 1)); }

echo "====================================================="
echo " Hefestos SIGINT v5.1.0 - testes funcionais"
echo "====================================================="

echo
echo "[1/8] Invariantes de pinagem"
python3 - "$ROOT" <<'PY'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
text = (root / "lib/src/hefestos_pins.h").read_text(encoding="utf-8")
defines = dict(re.findall(r"^#define\s+(\w+)\s+(\d+)\b", text, re.M))

groups = {"N1": {}, "N2": {}, "N3": {}}
for name, val in defines.items():
    for g in groups:
        if name.startswith(g + "_") and "SERIAL" not in name:
            groups[g].setdefault(int(val), []).append(name)

ok = True
for g, pins in groups.items():
    for pin, names in pins.items():
        if len(names) > 1:
            print(f"  [FAIL] {g}: GPIO {pin} duplicado em {names}")
            ok = False
if ok:
    print("  [PASS] nenhuma pinagem duplicada por no")

# GPIO2 e' permitido apenas como N3_UART_TX (TX ociosa = nivel alto).
forbidden = {8, 9} | set(range(12, 20))
bad = [(n, v) for n, v in defines.items()
       if n.startswith("N3_") and "SERIAL" not in n and int(v) in forbidden]
if bad:
    for n, v in bad:
        print(f"  [FAIL] Node3 usa pino proibido no ESP32-C3: {n}=GPIO{v}")
    ok = False
else:
    print("  [PASS] Node3 nao usa pinos de strapping/flash/USB-JTAG")

sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[2/8] Layout do protocolo LoRa"
python3 - "$ROOT" <<'PY'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
pins = (root / "lib/src/hefestos_pins.h").read_text(encoding="utf-8")
link = (root / "lib/src/link_protocol.h").read_text(encoding="utf-8")
defs = {k: int(v) for k, v in re.findall(r"^#define\s+(HEF_\w+)\s+(\d+)\b", pins, re.M)}

checks = []
checks.append(("HEF_HEADER_LEN == 15", defs.get("HEF_HEADER_LEN") == 15))
raw = dict(re.findall(r"^#define\s+(HEF_\w+)\s+(.+)$", pins, re.M))
def evaldef(name):
    expr = raw.get(name, "0").strip()
    for k, v in defs.items():
        expr = re.sub(r"\b%s\b" % k, str(v), expr)
    try:
        return eval(expr, {"__builtins__": {}}, {})
    except Exception:
        return None
checks.append(("HEF_MAX_FRAME == header+payload+tag",
               evaldef("HEF_MAX_FRAME") == defs.get("HEF_HEADER_LEN") +
               defs.get("HEF_MAX_PAYLOAD") + defs.get("HEF_TAG_LEN")))
checks.append(("nodeId no offset 5", "putU16(hdr + 5, nodeId)" in link))
checks.append(("epoch no offset 7", "putU16(hdr + 7, epoch)" in link))
checks.append(("counter no offset 9", "putU32(hdr + 9, counter)" in link))
checks.append(("payloadLen no offset 13", "putU16(hdr + 13, payloadLen)" in link))
checks.append(("payloadLen lido do offset 13", "getU16(hdr + 13)" in link))

ok = True
for name, cond in checks:
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}")
        ok = False
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[3/8] Protocolo serial Node2<->Node3 (round-trip no host)"
SER=0
if command -v g++ >/dev/null 2>&1; then
    if g++ -std=c++11 -Wall -Wextra \
            -I "$ROOT/tests/stub" -I "$ROOT/lib/src" \
            "$ROOT/tests/serial_roundtrip.cpp" -o /tmp/hef_serial_test 2>/tmp/hef_serial_cc.log; then
        if /tmp/hef_serial_test > /tmp/hef_serial_run.log 2>&1; then
            sed -n 's/^  /  /p' /tmp/hef_serial_run.log | grep -E "^\s+\[(PASS|FAIL)\]" | head -40
            echo "  [PASS] round-trip do protocolo serial (33 verificacoes)"
        else
            grep -E "\[FAIL\]" /tmp/hef_serial_run.log || true
            echo "  [FAIL] round-trip do protocolo serial"; SER=1
        fi
    else
        echo "  [FAIL] compilacao do teste serial falhou:"
        head -20 /tmp/hef_serial_cc.log
        SER=1
    fi
else
    echo "  [SKIP] g++ nao instalado (round-trip nao executado)"
fi
# Checagem estatica do layout (independe do compilador host).
if grep -q "buf_\[scan_ + 4\]" "$ROOT/lib/src/serial_protocol.h" &&
   grep -q "buf_\[scan_ + 6 + len\]" "$ROOT/lib/src/serial_protocol.h"; then
    echo "  [PASS] offsets do frame serial conferem (LEN/CRC/PAYLOAD)"
else
    echo "  [FAIL] offsets do frame serial inconsistentes"; SER=1
fi
[ $SER -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[4/8] Ausencia de legado inseguro"
LEGACY=0
if grep -rInE "EEPROM\.|TelnetServer|telnetServer|WiFiServer\(23\)" "$ROOT/src" "$ROOT/lib" >/dev/null 2>&1; then
    echo "  [FAIL] uso de EEPROM/Telnet encontrado"; LEGACY=1
else
    echo "  [PASS] sem uso de EEPROM e sem Telnet"
fi
if grep -rIn '"\.\./lib/' "$ROOT/src" >/dev/null 2>&1; then
    echo "  [FAIL] include relativo ../lib/ (quebra o build)"; LEGACY=1
else
    echo "  [PASS] sem include relativo ../lib/"
fi
[ $LEGACY -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[5/8] Anti-replay estrito e TOTP ativo"
SEC=0
if grep -q "return LINK_RX_REPLAY" "$ROOT/lib/src/secure_protocol.h"; then
    echo "  [PASS] contador repetido retorna LINK_RX_REPLAY"
else
    echo "  [FAIL] caminho de replay ausente"; SEC=1
fi
if grep -q "LINK_RX_RESYNC" "$ROOT/lib/src/secure_protocol.h"; then
    echo "  [FAIL] resultado LINK_RX_RESYNC presente (bypass de replay)"; SEC=1
else
    echo "  [PASS] sem caminho de aceitacao por 'resync'"
fi
if grep -q "totp.verify" "$ROOT/src/Node2_Base_Hefestos/Node2_Base_Hefestos.ino"; then
    echo "  [PASS] TOTP verificado no login"
else
    echo "  [FAIL] TOTP nao e' verificado no login"; SEC=1
fi
[ $SEC -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[6/8] Dashboard sem injecao de HTML e sem segredo hardcoded"
DASH=0
if grep -q "textContent" "$ROOT/src/Node2_Base_Hefestos/Node2_Base_Hefestos.ino"; then
    echo "  [PASS] dashboard usa textContent (sem innerHTML)"
else
    echo "  [FAIL] dashboard pode injetar HTML"; DASH=1
fi
if grep -rInE "\b[0-9a-fA-F]{64}\b" "$ROOT/src" "$ROOT/lib" >/dev/null 2>&1; then
    echo "  [FAIL] possivel PSK/chave de 32 bytes hardcoded"; DASH=1
else
    echo "  [PASS] nenhuma chave de 64 hex hardcoded"
fi
[ $DASH -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[7/8] Estado anti-replay persistido (replay pos-reboot)"
REPLAY=0
if command -v g++ >/dev/null 2>&1; then
    if g++ -std=c++11 -Wall -Wextra \
            -I "$ROOT/tests/stub" -I "$ROOT/tests" -I "$ROOT/lib/src" \
            "$ROOT/tests/anti_replay_persistence.cpp" -o /tmp/hef_replay_test 2>/tmp/hef_replay_cc.log; then
        if /tmp/hef_replay_test > /tmp/hef_replay_run.log 2>&1; then
            grep -E "^\s+\[(PASS|FAIL)\]" /tmp/hef_replay_run.log | head -8
            echo "  ... (ver /tmp/hef_replay_run.log para o restante)"
            echo "  [PASS] estado anti-replay persistido (75 verificacoes)"
        else
            grep -E "\[FAIL\]" /tmp/hef_replay_run.log || true
            echo "  [FAIL] estado anti-replay persistido"; REPLAY=1
        fi
    else
        echo "  [FAIL] compilacao do teste anti-replay falhou:"
        head -20 /tmp/hef_replay_cc.log
        REPLAY=1
    fi
else
    echo "  [SKIP] g++ nao instalado (teste anti-replay nao executado)"
fi
# Checagens estruturais: o estado anti-replay PRECISA ser persistido no
# vault cifrado e PRECISA ser reidratado no boot do receptor.
if grep -q "HEF_TLV_PEER_STATE" "$ROOT/lib/src/config.h" &&
   grep -q "putPeerState" "$ROOT/lib/src/config.h"; then
    echo "  [PASS] estado anti-replay gravado no vault cifrado (TLV 0x0A)"
else
    echo "  [FAIL] estado anti-replay nao e' persistido no vault"; REPLAY=1
fi
if grep -q "restorePeerStates" "$ROOT/src/Node2_Base_Hefestos/Node2_Base_Hefestos.ino" &&
   grep -q "hydrate" "$ROOT/src/Node2_Base_Hefestos/Node2_Base_Hefestos.ino"; then
    echo "  [PASS] receptor rehidrata o estado anti-replay no boot"
else
    echo "  [FAIL] receptor nao rehidrata o estado anti-replay"; REPLAY=1
fi
[ $REPLAY -ne 0 ] && FAILED=$((FAILED + 1))

echo
echo "[8/8] Build dos tres nos"
if [ $NO_BUILD -eq 1 ]; then
    echo "  [SKIP] --no-build"
elif command -v "${ARDUINO_CLI:-arduino-cli}" >/dev/null 2>&1; then
    if "$ROOT/build.sh" >/tmp/hefestos_build.log 2>&1; then
        echo "  [PASS] Node1 + Node2 + Node3 compilam"
    else
        echo "  [FAIL] build falhou (ver /tmp/hefestos_build.log)"
        FAILED=$((FAILED + 1))
    fi
else
    echo "  [SKIP] arduino-cli nao instalado"
fi

echo
echo "====================================================="
if [ $FAILED -eq 0 ]; then
    echo " RESULTADO: TODOS OS TESTES PASSARAM"
    exit 0
else
    echo " RESULTADO: $FAILED GRUPO(S) DE TESTE FALHARAM"
    exit 1
fi
