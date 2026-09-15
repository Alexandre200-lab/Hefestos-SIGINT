# HEFESTOS SIGINT v4.0 - Manual de Operação

## Acesso ao Sistema

### Dashboard Web
```
http://192.168.4.1
```
**Requer autenticação** via `/login` endpoint antes de acessar.

### Login HTTP
```bash
# POST com credenciais
curl -X POST -d "user=ADMIN_USER&pass=ADMIN_PASS" http://192.168.4.1/login

# Resposta: {"token":"<32hex>"}
# Usar token em header ou cookie:
#   Header: X-Hefestos-Token: <token>
#   Cookie: X-Hefestos-Token=<token>
```

### CLI Telnet
```
telnet 192.168.4.23
user: [username da EEPROM - gerado no 1º boot]
pass: [senha da EEPROM - gerada no 1º boot]
```
**Nota:** Credenciais são geradas aleatoriamente no primeiro boot via `esp_fill_random()`.
Consulte o serial output para obter as senhas, ou execute `factoryReset()`.

---

## Comandos CLI v4.0

### SISTEMA
```
help    - Lista comandos disponíveis
status  - Exibe status detalhado (RX, GCM OK/FAIL, RSSI, banda)
sair    - Encerra sessão e desconecta
```

### RÁDIO
```
freq <frequência>  - Define frequência (ex: freq 100.1)
band <banco>       - Define banda (FM, AM ou SW)
```

### Exemplos
```
> help
Comandos: help, status, freq, band, sair

> status
RX: 1234 | GCM OK: 1200 | FAIL: 34 | REPLAY: 5
RSSI: -75 dBm | Banda: FM | Freq: 100.1

> band AM
Banda: AM

> freq 1000
Freq: 1000.0
```

---

## HTTP Endpoints v4.0

### Autenticação
| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/login` | POST | Login e obtenção de token de sessão |
| `/logout` | POST | Encerra sessão e invalida token |

### Dados
| Endpoint | Método | Descrição | Auth |
|----------|--------|-----------|------|
| `/` | GET | Dashboard HTML | Sim |
| `/dados` | GET | Status JSON (mensagem, RSSI, contadores) | Sim |
| `/sintonizar` | GET | Controle rádio (banda, frequência) | Sim |

### V4.1 Novos Endpoints
| Endpoint | Método | Descrição | Auth |
|----------|--------|-----------|------|
| `/ota` | POST | Atualização OTA de firmware | Sim |
| `/jamming` | GET | Status de detecção de jamming | Sim |
| `/health` | GET | Status do sistema | Sim |

---

## Dashboard v4.0

### Indicadores
- **RX**: Total de pacotes recebidos
- **GCM OK**: Pacotes descriptografados com sucesso (AES-GCM)
- **GCM FAIL**: Falhas de descriptografia (chave incorreta ou dados corrompidos)
- **REPLAY**: Replay attacks detectados (contadores duplicados)
- **RSSI**: Força do sinal LoRa (dBm)
- **Banda/Freq**: Rádio atualmente sintonizado

### JSON `/dados`
```json
{
  "mensagem": "ALVO_01|-23.5505|-46.6333",
  "rssi": -75,
  "rx_count": 1234,
  "gcm_ok": 1200,
  "gcm_fail": 34,
  "replay_count": 5
}
```

### JSON `/jamming` (V4.1)
```json
{
  "jamming": "NORMAL",
  "snr": 85,
  "since": 0
}
```

### JSON `/ota` (V4.1)
```bash
# Exemplo de request
curl -X POST -H "X-Hefestos-Token: <token>" \
  -d "fw=HEF41ABC" http://192.168.4.1/ota

# Resposta
{"status":"accepted","firmware":"HEF4..."}
```

---

## Segurança v4.0

### Camadas de Proteção
| Camada | Proteção | Mecanismo |
|--------|----------|-----------|
| RF | Confidencialidade + Integridade | AES-256-GCM (mbedtls AEAD) |
| RF | Anti-Replay | Counter monotônico + SHA-256 nonce |
| RF | Channel Access | CSMA/CA LoRa (sense + backoff 1000ms) |
| HTTP | Autenticação | Session tokens (Bearer/Cookie) |
| HTTP | Anti-DoS | Rate limit (30 cmd/min) + cooldown 100ms |
| HTTP | Anti-Brute Force | IP block 30min após 3 tentativas |
| Telnet | Autenticação | Username + senha (constant-time compare) |
| Telnet | Session | Timeout 1min idle / 5min absoluto |
| Storage | Cifragem | AES-256-GCM com chave efuse MAC |
| Storage | Key Derivation | PBKDF2-HMAC-SHA256 (100k rounds) |
| RNG | Entropia | Hardware RNG (`esp_fill_random`) |

### Credenciais
- **NÃO existem credenciais padrão**
- Geradas aleatoriamente no 1º boot
- Consultar serial output para obter senhas
- Ou executar `factoryReset()` para regenerar

---

## Troubleshooting v4.0

### "REPLAY DETECTADO"
- Contador pacotes foi reutilizado
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
- Verificar distância entre Node1 e Node2

### "Rate limit exceeded"
- Mais de 30 comandos/minuto
- Aguardar 1 minuto para reset do contador

### "Session expired" / "Unauthorized"
- Timeout idle (30min) ou absoluto (4h) atingido
- Re-login necessário via `/login` endpoint

### SD Card Failure (Node3)
- 3 tentativas de init com retry automático
- Fallback para RAM buffer (256 slots)
- Re-check a cada 30 segundos
- Verificar cartão SD e conexões

### Serial Output Primeiro Boot
```
=== HEFESTOS SIGINT v4.0 ===
WiFi: Hefestos-SIGINT
WiFi Password: <SENHA_AQUI>
CLI User: <USUARIO_AQUI>
CLI Password: <SENHA_AQUI>
TOTP Secret: <SECRET_AQUI>
```
**Guarde estas credenciais!** Não são recuperáveis após o boot.

---

## Referência Rápida

### Node Pinagem
```
Node 1 (ESP32):
  LoRa SX1276:  CS(5), RST(14), DIO0(26), SPI(18,19,23)
  GPS NEO-6M:   RX(16), TX(17)
  TX FM:        SDA(21), SCL(22), RST(32)

Node 2 (ESP32):
  LoRa SX1276:  CS(5), RST(14), DIO0(26), SPI(18,19,23)
  RX Scanner:   SDA(21), SCL(22), RST(12)
  UART Node3:   TX(17), RX(16)

Node 3 (ESP32-C3):
  SD Card:      CS(4), MOSI(6), MISO(5), SCK(7)
  UART:         RX(20), TX(21)
  LEDs/Buzzer:  7, 8, 9
```

### Compilação
```bash
# Build completo
./build.sh

# Individual
arduino-cli compile -b esp32:esp32:esp32 src/Node1_Transmissor_Alvo/
arduino-cli compile -b esp32:esp32:esp32 src/Node2_Base_Hefestos/
arduino-cli compile -b esp32:esp32:esp32c3 src/Node3_Caixa_Preta_ESP32C3/
```

### Factory Reset
```cpp
// Executar via CLI ou serial
config.factoryReset()
// Gera novas credenciais e chaves aleatórias
// EEPROM criptografada com nova chave efuse MAC
```

---

## Versão

- **v4.1.0** - 2026-09-15
- **Status**: Production-ready (security hardened)
