# CHANGELOG - HEFESTOS SIGINT v4.0

## Data: 2026-07-24
## Status: Architecture Unification Complete

---

## v4.0.0 - Architecture Unification (2026-07-24)

### Major Changes

| Area | Change |
|------|--------|
| **Config** | Centralized `hefestos_pins.h` with all pin/EEPROM/constant definitions |
| **Build** | Unified `build.sh` compiling all 3 nodes from source |
| **Node1** | Refactored to use centralized pins, version bumped to v4.0 |
| **Node2** | Refactored to use centralized pins, removed duplicate defines, version v4.0 |
| **Node3** | **Migrated from Arduino Uno to ESP32-C3**: Native UART (no SoftwareSerial), LEDC PWM for buzzer, expanded RAM buffer (16→256 entries), direct 3.3V logic (no level shifter) |
| **EEPROM** | Unified address map (v4.0 magic 0x4848) |
| **LoRa** | Centralized frequency/SF/BW/TX power constants |

### Architecture Improvements

| # | Improvement | Impact |
|---|-------------|--------|
| 1 | Centralized pin/constant header | Single source of truth, no magic numbers |
| 2 | ESP32-C3 Node3 | 200x RAM (400KB vs 2KB), native USB, unified toolchain |
| 3 | Removed level shifter | Both ESP32 nodes now 3.3V logic |
| 4 | Build from source | Reproducible builds, no pre-compiled binaries |

### Hardware Changes (Node3)

| Component | Arduino Uno | ESP32-C3 | Benefit |
|-----------|-------------|----------|---------|
| MCU | ATmega328P (8-bit, 16MHz) | ESP32-C3 (RISC-V, 160MHz) | 200x performance |
| RAM | 2 KB | 400 KB | Buffer 16→256 entries |
| Flash | 32 KB | 4 MB | Full debug symbols |
| UART | 1 (SoftSerial for 2nd) | 2 Hardware | No timing issues |
| USB | UART-only | Native CDC | Direct Serial monitor |
| Logic | 5V | 3.3V | Matches Node2, no level shifter |

---

## v3.1.0 - Security Hardening (2026-07-15)

### Bibliotecas Reescritas

| Biblioteca | Linhas | Mudança |
|------------|--------|---------|
| `crypto_gcm.h` | ~100 | mbedtls GCM real (antes: AES-CTR+HMAC caseiro) |
| `secure_storage.h` | ~100 | PBKDF2 + AES-256-GCM (antes: LCG + XOR+ROT13) |
| `config.h` | ~220 | esp_fill_random(); credenciais hardcoded removidas |
| `rate_limiter.h` | ~125 | IP tracking removido (apenas hash) |
| `secure_protocol.h` | ~135 | Reset periódico removido |
| `totp_auth.h` | ~230 | generateRandomSecret() via HW RNG |

### Correções de Segurança

| # | Vulnerabilidade | Correção |
|---|----------------|----------|
| 1 | AES-GCM caseiro (CTR+HMAC, IV previsível) | mbedtls_gcm_crypt_and_tag AEAD |
| 2 | Key derivation LCG 5k rounds | PBKDF2-HMAC-SHA256 100k rounds |
| 3 | Geração de chaves via LCG | esp_fill_random() (hardware RNG) |
| 4 | Telnet auth sem username | Username + senha verificados |
| 5 | Replay window de 60s | Counter monotônico (sem reset) |
| 6 | Credenciais hardcoded no código/README | Geradas aleatoriamente no 1º boot |
| 7 | TOTP secret RFC test vector | Gerado via esp_fill_random() |
| 8 | Buffer overflow potencial | Bounds check + GCM real (tamanhos fixos) |
| 9 | IP tracking em plaintext | Apenas hash anônimo |
| 10 | XOR+ROT13 pseudo-criptografia | Removido |
| 11 | Sessão telnet sem timeout | 1min idle / 5min absoluto |
| 12 | Brute force sem bloqueio de IP | IP bloqueado 30min após 3 tentativas |
| 13 | HTTP sem validação de input | Range validado (banda/frequência) |
| 14 | Build artifacts no repo | Adicionados ao .gitignore |
| 15 | Hex literal inválido 0xHEF3 | Corrigido para 0x1EF3 |

### Arquivos Modificados

| Arquivo | Mudanças |
|---------|----------|
| `src/lib/config.h` | loadDefaults() segura; esp_fill_random(); includes |
| `src/lib/crypto_gcm.h` | **Reescrito** com mbedtls GCM; SecurePacket removido |
| `src/lib/secure_storage.h` | **Reescrito** com PBKDF2 + AES-256-GCM |
| `src/lib/secure_protocol.h` | Reset periódico removido; 0xHEF3 → 0x1EF3 |
| `src/lib/rate_limiter.h` | ip_string removido; parâmetros limpos |
| `src/lib/totp_auth.h` | generateRandomSecret(); include esp_random.h |
| `src/Node2_Base_Hefestos.ino` | Auth fix; session timeout; brute force; sanitização |
| `.gitignore` | Build artifacts adicionados |
| `README.md` | Atualizado para v3.1 |

### Aviso
Credenciais anteriores foram removidas do código. Faça factoryReset() se atualizando de v3.0.  
Histórico git contém credenciais expostas — use BFG Repo-Cleaner para purgar.

---

## v3.0 - Security Critical Update (2026-04-20)

### Novas Bibliotecas Criadas

| Biblioteca | Linhas | Descrição |
|------------|--------|-----------|
| `crypto_gcm.h` | ~180 | AES-GCM autenticado |
| `secure_protocol.h` | ~120 | Nonce/Counter anti-replay |
| `totp_auth.h` | ~180 | 2FA TOTP RFC 6238 |
| `secure_storage.h` | ~130 | Encrypt at rest |

### Correções de Segurança

| # | Vulnerabilidade | Correção |
|---|----------------|----------|
| 1 | HMAC sobre ciphertext | AES-GCM (AEAD) |
| 2 | Replay attacks | SecureProtocol counter |
| 3 | Rate limiter hash fixo | IP real por cliente |
| 4 | Username "admin" hardcoded | EEPROM configurável |
| 5 | Sem 2FA real | TOTP disponível |
| 6 | EEPROM texto puro | SecureStorage disponível |

### Arquivos Modificados

| Arquivo | Mudanças |
|---------|----------|
| `config.h` | +CLI_USER, v3.0 magic |
| `rate_limiter.h` | +allowCommand(IP real) |
| `Node1.ino` | AES-GCM + SecureProtocol |
| `Node2.ino` | AES-GCM + anti-replay detection |
| `Node3.ino` | Mantido (Arduino) |

### Documentação Atualizada

- `README.md` → v3.0
- `IMPLEMENTATION_GUIDE_v2.md` → v3.0
- `OPERATION_MANUAL_v2.md` → v3.0

---

## v2.1 - Anterior

### Melhorias
- HMAC-SHA256 real via mbedtls
- Verificação HMAC em Node2
- Chaves AES únicas no boot
- GPS validation

---

## v2.0 - Refactoring

### Melhorias
- EEPROM Config Manager
- WiFi forte (22 chars)
- Autenticação Telnet 2FA
- Rate Limiting
- CRC16 UART
- SD Card Recovery

---

## Versão

- **Atual**: 3.1.0
- **Data**: 2026-07-15