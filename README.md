# HEFESTOS SIGINT: Estação Tática SIGINT Multi-Banda (v4.0)

Sistema avançado de Inteligência de Sinais (SIGINT), guerra eletrônica e telemetria com arquitetura Master-Slave distribuída. Realiza rastreamento GPS criptografado (AES-GCM), transmissão via LoRa (915 MHz Sub-GHz), interceptação de RF (AM/FM/SW), e retenção forense em SD Card com autenticação 2FA.

## Versão 4.0 - Architecture Unification (Jul 2026)

### Principais Mudanças v4.0

| Área | Mudança |
|------|---------|
| **Config** | Header centralizado `hefestos_pins.h` (pins, EEPROM, limites) |
| **Build** | Script unificado `build.sh` — compila os 3 nós do zero |
| **Node1** | Refatorado para pins centralizados, CSMA/CA no LoRa |
| **Node2** | Session-based HTTP auth, StaticJson, String→char arrays |
| **Node3** | **Migrado Arduino Uno → ESP32-C3**: HardwareSerial nativo, LEDC PWM, buffer RAM 16→256, 3.3V logic (sem level shifter) |
| **EEPROM** | Criptografada com chave derivada do efuse MAC (AES-256-GCM + PBKDF2 100k) |
| **HTTP** | Session tokens (Bearer/Cookie), idle 30min / absolute 4h, rate limit |
| **LoRa** | Nonce derivado SHA-256 (elimina padrão de counter), RNG check |

### Correções de Segurança v4.0

| # | Vulnerabilidade | Correção |
|---|----------------|----------|
| 1 | EEPROM plaintext (chaves AES, senhas) | AES-256-GCM com chave única por chip (efuse MAC) |
| 2 | HTTP sem autenticação | Session tokens obrigatórios em `/`, `/dados`, `/sintonizar` |
| 3 | Nonce previsível (counter + random) | SHA-256(counter || random_4B) → 12B nonce |
| 4 | RNG failure silencioso | `isRNGReady()` retorna erro -2 |
| 5 | `secureCompare` lê além do `\0` | Compara `strlen` real + constant-time |
| 6 | `blocked_since = 0` persistia bloqueio eterno | Expira no boot (`millis() - BLOCK_DURATION - 1`) |
| 7 | `DynamicJsonDocument` fragmenta heap | `StaticJsonDocument<1024>` na stack |
| 8 | `String` dinâmico em loops | `char[]` fixo elimina fragmentação |
| 9 | LoRa sem CSMA/CA | Channel sense + random backoff antes de TX |

### Bibliotecas de Segurança Revisadas
| Biblioteca | Descrição | Mudanças |
|------------|-----------|----------|
| `crypto_gcm.h` | AES-GCM autêntico (mbedtls) | **Reescrito**: agora usa `mbedtls_gcm_crypt_and_tag` AEAD real (antes: AES-CTR + HMAC truncado caseiro) |
| `secure_protocol.h` | Nonce/Counter anti-replay | Reset periódico removido (elimina janela de replay de 60s) |
| `totp_auth.h` | 2FA TOTP (RFC 6238) | `generateRandomSecret()` via hardware RNG (`esp_fill_random`) |
| `secure_storage.h` | Encrypt at rest | **Reescrito**: key derivation via PBKDF2-HMAC-SHA256 100k iterações; AES-256-GCM (antes: LCG caseiro + XOR+ROT13) |
| `config.h` | Gerenciamento de chaves | `esp_fill_random()` no lugar de LCG; credenciais hardcoded removidas |
| `rate_limiter.h` | Anti-DoS | IP tracking removido (privacidade); apenas hash anônimo |

### Correções de Segurança v3.1
| Correção | Antes | Depois |
|----------|-------|--------|
| **Telnet Auth** | Apenas senha verificada (username ignorado) | Username **e** senha verificados |
| **Session Timeout** | Ilimitado | 1 min idle / 5 min absoluto |
| **Brute Force** | 3 tentativas = reset conexão | 3 tentativas = IP bloqueado por 30 min |
| **Senha em echo** | Caracteres visíveis na digitação | Exibe `*` durante digitação da senha |
| **AES-GCM** | AES-CTR + HMAC-8 (não-AEAD, IV previsível) | `mbedtls_gcm` AEAD real (12B nonce + random, tag 16B) |
| **Key Derivation** | LCG 5k rounds | PBKDF2-HMAC-SHA256 100k rounds |
| **Geração de chaves** | LCG baseado em MAC+heap+reset | `esp_fill_random()` (hardware RNG) |
| **Anti-Replay** | Reset a cada 60s (janela de replay) | Monotônico (uint32_t = 8000 anos sem overflow) |
| **Encrypt-at-Rest** | AES-CTR (assinatura errada) + XOR+ROT13 | AES-256-GCM autêntico |
| **HTTP /sintonizar** | Sem validação de input | Range validado (banda/frequência) |
| **Credenciais hardcoded** | Presentes em `config.h` e README | Removidas — geradas aleatoriamente no 1º boot |
| **TOTP Secret** | RFC test vector (`JBSWY3DPEHPK3PXP`) | Gerado via `esp_fill_random()` |
| **Rate Limiter** | IP armazenado em plaintext | Apenas hash anônimo |
| **Build artifacts** | `.bin`, `.elf`, `.map` no repo | Adicionados ao `.gitignore` |

### Aviso de Segurança
**Credenciais anteriores foram removidas permanentemente do código.**  
Se você atualizou de uma versão anterior, execute `factoryReset()` ou limpe a EEPROM.  
O histórico do git ainda contém credenciais expostas — use `git filter-branch` ou BFG Repo-Cleaner para purgar.

---

## Arquitetura do Sistema

### 1. Node 1 (Transmissor/Alvo - ESP32)
- GPS polling (1000ms)
- Criptografia AES-GCM com nonce+counter
- Transmissão LoRa 915 MHz
- Transmissor FM (Si4713)

### 2. Node 2 (Base Hefestos - ESP32)
- Servidor HTTP/Dashboard
- CLI Telnet com rate limiting
- Interceptação LoRa com verificação GCM
- Detecção de replay attacks
- Controle rádio (AM/FM/SW)

### 3. Node 3 (Caixa Preta - Arduino)
- Log forense em SD Card
- CRC16 UART
- RAM fallback (50 slots)
- LEDs/Buzzer

---

## Segurança v3.0

### Proteções Implementadas
| Camada | Proteção | Mecanismo |
|-------|----------|-----------|
| RF | AEAD | AES-GCM (128-bit, mbedtls) |
| RF | Anti-Replay | Nonce + Counter monotônico |
| RF | Confidencialidade | Criptografia autenticada |
| UART | Integridade | CRC16 |
| API | Autenticação | 2FA TOTP + Rate Limit |
| API | DoS | 30 cmd/min + cooldown 100ms |
| API | Brute Force | Block IP por 30 min após 3 tentativas |
| Storage | Cifragem | AES-256-GCM via PBKDF2 |
| Session | Timeout | 1 min idle / 5 min absoluto |

> **Nota**: Credenciais são geradas aleatoriamente no primeiro boot via hardware RNG (`esp_fill_random`).  
> Não existem credenciais padrão. Consulte o serial output no primeiro boot para obter as senhas,  
> ou configure via `config.h` antes da compilação.

---

## Pinagem (inalterada)

### Node 1 (ESP32)
```
LoRa SX1276:  CS(5), RST(14), DIO0(26), SPI(18,19,23)
GPS NEO-6M:    RX(16), TX(17)
TX FM:        SDA(21), SCL(22), RST(32)
```

### Node 2 (ESP32)
```
LoRa SX1276:  CS(5), RST(14), DIO0(26), SPI(18,19,23)
RX Scanner:    SDA(21), SCL(22), RST(12)
UART Node3:   TX(17), RX(16)
```

### Node 3 (Arduino)
```
SD Card:      CS(4), MOSI(11), MISO(12), SCK(13)
UART:        RX(0), TX(1)
LEDs/Buzzer: 7, 8, 9
```

---

## Compilação

```bash
# ESP32 boards
arduino-cli core install esp32:esp32
arduino-cli core install arduino:avr

# Compilar Node1
arduino-cli compile -b esp32:esp32:esp32 src/Node1_Transmissor_Alvo/

# Compilar Node2
arduino-cli compile -b esp32:esp32:esp32 src/Node2_Base_Hefestos/

# Compilar Node3
arduino-cli compile -b arduino:avr:uno src/Node3_Caixa_Preta_Arduino/
```

---

## Vulnerabilidades Corrigidas

| Versão | Vulnerabilidade | Status |
|--------|--------------|--------|
| v2.1 | HMAC sobre ciphertext | ✅ CORRIGIDO |
| v2.1 | Rate limiter hash fixo | ✅ CORRIGIDO |
| v2.1 | Username "admin" hardcoded | ✅ CORRIGIDO |
| v2.1 | Sem 2FA real | ✅ ADICIONADO |
| v2.1 | EEPROM texto puro | ✅ CORRIGIDO |
| v3.1 | AES-GCM caseiro (CTR+HMAC truncado) → mbedtls GCM real | ✅ CORRIGIDO |
| v3.1 | Key derivation LCG → PBKDF2 100k iters | ✅ CORRIGIDO |
| v3.1 | Telnet auth sem username | ✅ CORRIGIDO |
| v3.1 | Replay window 60s | ✅ CORRIGIDO |
| v3.1 | Credenciais hardcoded no código/README | ✅ REMOVIDO |
| v3.1 | TOTP secret RFC test vector | ✅ CORRIGIDO |
| v3.1 | Buffer overflow potencial em crypto | ✅ CORRIGIDO |
| v3.1 | IP tracking em plaintext | ✅ CORRIGIDO |
| v3.1 | XOR+ROT13 pseudo-criptografia | ✅ REMOVIDO |
| v3.1 | Sessão telnet sem timeout | ✅ ADICIONADO |
| v3.1 | Brute force sem bloqueio de IP | ✅ ADICIONADO |
| v3.1 | Build artifacts no repo | ✅ .gitignore |

---

## Documentação

| Documento | Conteúdo |
|-----------|---------|
| `IMPLEMENTATION_GUIDE_v2.md` | Arquitetura v3.0, segurança (desatualizado) |
| `OPERATION_MANUAL_v2.md` | CLI, dashboard v3.0 (desatualizado) |
| `dependencias.txt` | Bibliotecas |

---

## Versão

- **Versão atual**: 3.1.0
- **Data**: 2026-07-15
- **Status**: Production-ready (security hardened)
- **Compatibilidade**: ESP32, Arduino Uno/Mega

---

## Changelog

### v3.1.0 (2026-07-15) — Security Hardening
- **Criptografia**: AES-GCM real (mbedtls) substitui AES-CTR+HMAC caseiro
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100k iters) substitui LCG (5k iters)
- **RNG**: Hardware RNG (`esp_fill_random`) substitui LCG
- **Telnet**: Auth com username+senha; session timeout; brute force blocking por IP
- **Credenciais**: Removidas do código e README — geradas aleatoriamente no 1º boot
- **TOTP**: Secret gerado via hardware RNG
- **Anti-Replay**: Reset periódico removido (era janela de 60s)
- **Rate Limiter**: IP tracking removido (apenas hash anônimo)
- **Encrypt-at-Rest**: AES-256-GCM (antes: AES-CTR quebrado + XOR+ROT13)
- **HTTP**: Validação de parâmetros no endpoint /sintonizar
- **Git**: Build artifacts adicionados ao .gitignore
- **Hex fix**: `0xHEF3` inválido → `0x1EF3`

### v3.0.0 (2026-04-20)
- AES-GCM, anti-replay, TOTP 2FA, secure storage