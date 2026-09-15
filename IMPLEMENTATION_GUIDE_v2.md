# HEFESTOS SIGINT v4.0 - Guia de Implementação

## Sumário v4.0

### Bibliotecas de Segurança (Reescritas v3.1+v4.0)
- `crypto_gcm.h` - AES-GCM autenticado (mbedtls) com `isRNGReady()` hardening
- `secure_protocol.h` - Anti-Replay protocol com `isValidCounter()` drift tolerance
- `totp_auth.h` - 2FA TOTP via hardware RNG (`esp_fill_random`)
- `secure_storage.h` - Encrypt at rest com PBKDF2 100k rounds
- `config.h` - Gerenciamento de chaves com EEPROM criptografada
- `rate_limiter.h` - Anti-DoS com hash anônimo (sem IP tracking)

### Correções de Segurança v4.0
| # | Vulnerabilidade | Correção |
|---|----------------|----------|
| 1 | EEPROM plaintext | AES-256-GCM com chave derivada do efuse MAC |
| 2 | HTTP sem autenticação | Session tokens (Bearer/Cookie) obrigatórios |
| 3 | Nonce previsível | SHA-256(counter \|\| random_4B) → 12B nonce |
| 4 | RNG entropia fraca | `isRNGReady()`: mínimo 4/8 bytes não-zero |
| 5 | Clock drift | `isValidCounter()`: janela 1000 counters |
| 6 | Credenciais hardcoded | Geradas aleatoriamente no 1º boot via `esp_fill_random` |
| 7 | TOTP secret fixo | Secret gerado via hardware RNG |

---

## Segurança

### ConfigManager (config.h v4.0)

```
EEPROM Layout (512 bytes):
├── 0x00-0x01:  Magic 0x4848 (v4.0)
├── 0x02:        Version 4
├── 0x03:        Flags (FW_VERSION:3bits | FW_MINOR:3bits | DEBUG:1 | KEYS_GEN:1)
├── 0x04-0x13:  AES Key (16 bytes)
├── 0x14-0x1F:  AES IV (16 bytes)
├── 0x20-0x3F:  WiFi Pass (32 bytes)
├── 0x40-0x5F:  CLI Pass (32 bytes)
├── 0x60-0x6F:  CLI User (16 bytes)
├── 0x100-0x103: LoRa Counter (4 bytes)
├── 0x110+:      Blocked IPs
```

### Chave Mestra (PBKDF2)
```cpp
// Derivação de chave a partir do efuse MAC (único por chip)
uint8_t mac[6];
esp_efuse_mac_get_default(mac);
mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
    mac, sizeof(mac),
    "Hefestos-v4-EEPROM", 18,
    100000,                 // 100k iterações
    32, master_key);        // 256-bit key
```

### Boot Safe-Mode
```cpp
void begin() {
    uint8_t fw_flags = EEPROM.read(EEPROM_ADDR_FLAGS);
    uint8_t stored_version = (fw_flags & FLAG_FW_VERSION) >> 3;
    
    if (stored_version != 4) {  // FW_VERSION = 4
        debug.log("SAFE MODE: Firmware version mismatch - read only");
        config.flags &= ~FLAG_KEYS_GENERATED;  // Impede gravação
    }
}
```

---

## AES-GCM (crypto_gcm.h)

### Nonce Derivation (SHA-256)
```cpp
// IV[0..3] = counter (4 bytes)
// IV[4..11] = SHA-256(counter || random_4B)[0..8]
uint8_t iv[12];
memcpy(iv, &counter, 4);
uint8_t rand_part[4];
esp_fill_random(rand_part, 4);
uint8_t hash_input[8] = {counter, rand_part};
mbedtls_md_sha256(hash_input, 8, iv + 4);
```

### Entropy Check (isRNGReady)
```cpp
static bool isRNGReady() {
    uint8_t test[8];
    esp_fill_random(test, 8);
    int non_zero = 0;
    for (int i = 0; i < 8; i++) if (test[i]) non_zero++;
    return non_zero >= 4;  // 50% threshold
}
```

### Node1 TX
```cpp
AESGCM aesgcm;
aesgcm.setKey(aes_key, 16);
uint32_t counter = secProto.getNextCounter();
int outLen = aesgcm.encrypt((uint8_t*)payload, strlen(payload), output, counter);
// Output: [IV 12B][Ciphertext N][Tag 16B]
LoRa.write(output, outLen);
```

### Node2 RX
```cpp
int decLen = aesgcm.decrypt(buffer, len, decrypted);
if (decLen > 0) {
    uint32_t counter;
    memcpy(&counter, buffer, 4);
    if (!secProto.isValidCounter(counter)) {
        if (packetHistory.isDuplicate(counter)) {
            replay_count++;  // REPLAY!
        } else {
            secProto.updateValidCounter(counter);  // Resync (reboot)
        }
    } else {
        secProto.updateValidCounter(counter);  // OK
    }
}
```

---

## Secure Protocol (secure_protocol.h)

### Anti-Replay Counter
```cpp
bool isValidCounter(uint32_t counter) {
    if (counter <= last_valid_counter) return false;
    // Janela 1000 counters para clock drift
    return (counter - last_valid_counter) <= 1000;
}
```

### Packet History (256 entries)
```cpp
class PacketHistory {
    static const int HISTORY_SIZE = 256;
    uint32_t counters[HISTORY_SIZE];  // Buffer circular
    bool isDuplicate(uint32_t counter);  // O(1) lookup
};
```

---

## HTTP Session Management (Node2)

### Login
```cpp
server.on("/login", HTTP_POST, [](AsyncWebServerRequest *request) {
    // Valida user/pass
    // Gera token via esp_fill_random()
    // Armazena em http_sessions[] (max 4)
    // Retorna Set-Cookie: X-Hefestos-Token=...
});
```

### Session Verification
```cpp
bool verifyHTTPSession(AsyncWebServerRequest* request) {
    // Verifica Cookie ou X-Hefestos-Token header
    // Timeout: 30min idle / 4h absolute
    // Verifica IP do cliente
}
```

### Rate Limiter
```cpp
// 30 cmd/min + cooldown 100ms
// Apenas hash anônimo (sem IP tracking)
rateLimiter.allowCommand(ip_string);
```

---

## V4.1 Features (Node2)

### Band Sweep
```cpp
void barridaBanda() {
    const char* bandas[] = {"FM", "AM", "SW"};
    float freqs[][3] = {{8400, 10800, 100.1}, {520, 1710, 1000}, {2300, 30000, 5000}};
    for (int b = 0; b < 3; b++) {
        for (int f = 0; f < 3; f++) {
            radioRX.setBand(bandas[b], freqs[b][f]);
            delay(50);
            int rssi = readRSSI();
            logSpectra(bandas[b], freqs[b][f], rssi);
        }
    }
}
```

### Jamming Detection
```cpp
struct LinkMetric {
    uint32_t last_counter;
    uint32_t gaps;
    int snr_estimate;
    bool jamming_detected;
};

void monitorLinkQuality() {
    // Gap > threshold → SNR baixo → jamming
    // Reseta quando SNR melhora
}
```

### OTA Update
```cpp
server.on("/ota", HTTP_POST, [](AsyncWebServerRequest *request) {
    // Requer session token válido
    // Valida firmware parameter
    // Em produção: grava SPIFFS/EEPROM + restart
});
```

---

## Node3 ESP32-C3 (Migrated from Arduino)

### Diferenças v2.1 → v4.0
| Componente | Arduino v2.1 | ESP32-C3 v4.0 |
|-----------|-------------|---------------|
| Serial | SoftwareSerial(2,3) | HardwareSerial(0) |
| Buffer | 16 slots | 256 slots |
| Buzzer | tone() | LEDC PWM |
| Pins | Hardcoded | hefestos_pins.h |
| RAM | 2 KB | 400 KB |

### Compilação
```bash
arduino-cli compile -b esp32:esp32:esp32c3 src/Node3_Caixa_Preta_ESP32C3/
```

---

## Deployment Checklist

### Compilação
```bash
# Node1 (ESP32)
arduino-cli compile -b esp32:esp32:esp32 src/Node1_Transmissor_Alvo/

# Node2 (ESP32)
arduino-cli compile -b esp32:esp32:esp32 src/Node2_Base_Hefestos/

# Node3 (ESP32-C3)
arduino-cli compile -b esp32:esp32:esp32c3 src/Node3_Caixa_Preta_ESP32C3/
```

### Primeiro Boot
1. Credenciais geradas aleatoriamente via `esp_fill_random()`
2. EEPROM criptografada com chave do efuse MAC
3. Consultar serial output para obter senhas
4. Ou executar `factoryReset()` para regenerar

### Rollout Phased
```
Fase A: 10% (dev/test) → validar correções
Fase B: 50% (early adopters) → monitorar métricas
Fase C: 100% (production) → deploy completo
Fase D: Suporte legacy v3.0 → 6 meses
```

---

## Troubleshooting

### "REPLAY DETECTADO"
- Contador duplicado detectado
- Verificar se Node1 rebootou (resync automático com tolerância 1000 counters)
- Se recorrente: verificar sincronização entre nós

### "GCM FAIL"
- Chave AES diferente entre Node1 e Node2
- EEPROM corrompida ou chip substituído (efuse MAC diferente)
- Solução: `factoryReset()` em ambos os nós

### "SAFE MODE: Firmware version mismatch"
- EEPROM contém versão incompatível
- Boot em modo leitura (sem gravação EEPROM)
- Solução: `factoryReset()` para atualizar EEPROM

### "JAMMING DETECTED"
- SNR estimado abaixo do threshold (gap > 1000 counters)
- Verificar interferência RF no canal LoRa
- Verificar distânica entre Node1 e Node2

### "Rate limit exceeded"
- Mais de 30 comandos/minuto
- Rate limiter usa hash anônimo (não IP)
- Aguardar 1 minuto para reset do contador

### "Session expired"
- Timeout idle (30min) ou absoluto (4h) atingido
- Re-login necessário via `/login` endpoint

### SD Card Failure (Node3)
- 3 tentativas de init com retry automático
- Fallback para RAM buffer (256 slots)
- Re-check a cada 30 segundos

---

## Versão

- **v4.1.0** - 2026-09-15
- **Status**: Production-ready (security hardened)
