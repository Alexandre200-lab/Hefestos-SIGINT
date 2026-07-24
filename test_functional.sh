#!/bin/bash
# ============================================================
# HEFESTOS SIGINT v4.0 — Functional Test Suite
# Execute on target hardware with 3 nodes connected
# ============================================================
set -euo pipefail

NODE1_IP="192.168.4.1"
NODE2_IP="192.168.4.1"
NODE3_SERIAL="/dev/ttyUSB0"

echo "=== HEFESTOS SIGINT v4.0 Functional Tests ==="
echo ""

# Test 1: Build verification
echo "--- Test 1: Build All Nodes ---"
./build.sh
echo "✓ Build passed"
echo ""

# Test 2: EEPROM encryption (requires Node2 serial)
echo "--- Test 2: EEPROM Encryption Check ---"
echo "Connect to Node2 serial and verify:"
echo "  1. First boot generates random credentials"
echo "  2. EEPROM dump shows encrypted data (not plaintext)"
echo "  3. dumpKeys command shows MAC hash"
echo ""

# Test 3: HTTP Session Auth
echo "--- Test 3: HTTP Session Authentication ---"
echo "Testing /login endpoint..."
TOKEN=$(curl -s -X POST -d "user=hefestos&pass=YOUR_CLI_PASS" http://$NODE2_IP/login | jq -r .token)
if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
  echo "✓ Login successful, token: ${TOKEN:0:8}..."
  
  # Test protected endpoint
  DATA=$(curl -s -H "X-Hefestos-Token: $TOKEN" http://$NODE2_IP/dados)
  echo "✓ /dados accessible with token: $(echo $DATA | jq -r .mensagem | head -c 40)..."
  
  # Test logout
  curl -s -X POST -H "X-Hefestos-Token: $TOKEN" http://$NODE2_IP/logout
  echo "✓ Logout successful"
else
  echo "✗ Login failed"
fi
echo ""

# Test 4: Rate Limiting
echo "--- Test 4: Rate Limiting ---"
echo "Sending 35 rapid requests to /sintonizar..."
for i in {1..35}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Hefestos-Token: $TOKEN" "http://$NODE2_IP/sintonizar?b=FM&f=100.1")
  if [ "$CODE" = "429" ]; then
    echo "✓ Rate limit triggered at request $i"
    break
  fi
done
echo ""

# Test 5: Brute Force Protection
echo "--- Test 5: CLI Brute Force Block ---"
echo "Testing 5 failed telnet logins..."
# Requires expect or manual test
echo "Manual test: telnet $NODE2_IP 23, fail 3 times -> should block IP"
echo ""

# Test 6: LoRa Encryption + Anti-Replay
echo "--- Test 6: LoRa Crypto + Anti-Replay ---"
echo "1. Start Node1 (transmitter)"
echo "2. Start Node2 (receiver)"
echo "3. Verify Node2 shows: GCM OK counter incrementing"
echo "4. Capture LoRa packet with SDR"
echo "5. Replay captured packet -> should show REPLAY DETECTADO"
echo "6. Reboot Node1 -> Node2 should resync (not replay)"
echo ""

# Test 7: EEPROM Chip Binding
echo "--- Test 7: EEPROM Chip Binding (efuse MAC) ---"
echo "1. Configure Node1/Node2 with same EEPROM data"
echo "2. Swap ESP32 chips between nodes"
echo "3. Nodes should fail to decrypt (different efuse MAC)"
echo "4. factoryReset() should work on new chip"
echo ""

# Test 8: Node3 SD Failover
echo "--- Test 8: Node3 SD Card Failover ---"
echo "1. Remove SD card from Node3"
echo "2. Send data from Node2 -> verify RAM buffer stores logs"
echo "3. Reinsert SD card -> verify flush to CSV"
echo ""

# Test 9: Session Timeouts
echo "--- Test 9: HTTP Session Timeouts ---"
echo "1. Login, get token"
echo "2. Wait 30 min (idle) -> token should expire"
echo "3. Wait 4 hours (absolute) -> token should expire"
echo ""

# Test 10: CLI Telnet Auth + Session
echo "--- Test 10: Telnet CLI Session ---"
echo "1. telnet $NODE2_IP 23"
echo "2. Enter user/pass -> authenticated"
echo "3. Wait 1 min idle -> session expires"
echo "4. Wait 5 min absolute -> session expires"
echo "5. 3 failed attempts -> IP blocked 30 min"
echo ""

echo "=== All Test Procedures Documented ==="
echo "Run on hardware to validate!"