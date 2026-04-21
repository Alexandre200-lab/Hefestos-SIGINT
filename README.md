# HEFESTOS SIGINT: Estação Tática SIGINT Multi-Banda (v3.0)

Sistema avançado de Inteligência de Sinais (SIGINT), guerra eletrônica e telemetria com arquitetura Master-Slave distribuída. Realiza rastreamento GPS criptografado (AES-GCM), transmissão via LoRa (915 MHz Sub-GHz), interceptação de RF (AM/FM/SW), e retenção forense em SD Card com autenticação 2FA.

## Versão 3.0 - Segurança Crítica

### Novas Bibliotecas de Segurança
| Biblioteca | Descrição |
|------------|-----------|
| `crypto_gcm.h` | AES-GCM autenticado (elimina replay attack) |
| `secure_protocol.h` | Nonce/Counter anti-replay |
| `totp_auth.h` | 2FA TOTP (RFC 6238) |
| `secure_storage.h` | Encrypt at rest |

### Correções de Segurança v3.0
- **AES-GCM**: Substituído HMAC+Básico por criptografia autenticada
- **Anti-Replay**: Contador único por pacote
- **Rate Limiter**: IP real (não mais hashfixo)
- **Username configurável**: Não mais hardcoded "admin"
- **TOTP disponível**: 2FA real compat com Google Authenticator

### v2.1 Mantidas
- EEPROM Config Manager com chaves AES
- WiFi forte (22 chars)
- Autenticação Telnet 2FA
- Rate Limiting (30 cmd/min, 100ms cooldown)
- CRC16 em UART
- SD Card Recovery + RAM fallback

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
| RF | AEAD | AES-GCM (128-bit) |
| RF | Anti-Replay | Nonce + Counter |
| RF | Confidencialidade | Criptografia |
| UART | Integridade | CRC16 |
| API | Autenticação | 2FA + Rate Limit |
| API | DoS | 30 cmd/min |
| Storage | Cifragem | SecureStorage |

### Credenciais Padrão
```
WiFi SSID:    Hefestos-SIGINT
WiFi Pass:    Hefestos2024!SecureNet

Telnet User:  hefestos        (v3.0 - novo default)
Telnet Pass:  HefestosTactical@2024

AES Key:       HefestosTactica\0
```

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
| v2.1 | Username "admin" | ✅ CORRIGIDO |
| v2.1 | Sem 2FA real | ✅ ADICIONADO |
| v2.1 | EEPROM texto puro | ✅ DISPONÍVEL |

---

## Documentação

| Documento | Conteúdo |
|-----------|---------|
| `IMPLEMENTATION_GUIDE_v3.md` | Arquitetura v3.0, segurança |
| `OPERATION_MANUAL_v3.md` | CLI, dashboard v3.0 |
| `dependencias.txt` | Bibliotecas |

---

## Versão

- **Versão atual**: 3.0.0
- **Data**: 2026-04-20
- **Status**: Production-ready
- **Compatibilidade**: ESP32, Arduino Uno/Mega