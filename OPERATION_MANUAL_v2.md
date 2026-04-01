# HEFESTOS SIGINT v2.1 - Manual de Operação

## 🎯 Operação Rápida

### 1. Conectar ao Sistema

**Via Web (Dashboard):**
```
http://192.168.4.1
```

**Via Telnet (CLI Completo):**
```bash
telnet 192.168.4.1 23
user: admin
pass: HefestosTactical@2024
```

---

## 🕹️ Comandos CLI Disponíveis

### TELEMETRIA

#### `target`
Exibe as últimas coordenadas GPS decodificadas do alvo.

```
hefestos@base:~# target

[ PAYLOAD DECODIFICADO ]
Conteudo: ID:ALVO_01|Lat:-23.5505|Lon:-46.6333
```

#### `map`
Gera URL do Google Maps com as coordenadas do alvo.

```
hefestos@base:~# map

[ RASTREAMENTO SATELITAL ]
https://maps.google.com/maps?q=-23.5505,-46.6333
```

---

### SIGINT (INTELIGÊNCIA DE SINAIS)

#### `sniff`
Exibe o último pacote bruto interceptado na frequência 915 MHz.

```
hefestos@base:~# sniff

[ INTERCEPTACAO DE DADOS BRUTOS ]
Raw: \x48\x65\x66\x65\x73\x74\x6F\x73...
```

#### `history`
Despeja buffer de memória com as últimas interceptações (últimas 15 mensagens).

```
hefestos@base:~# history

[ BUFFER DE REDE RF ]
[SINAL -72dBm] ID:ALVO_01|Lat:-23.5500|Lon:-46.6330
[SINAL -75dBm] BEACON|Type:Unknown
[SINAL -80dBm] ID:ALVO_01|Lat:-23.5505|Lon:-46.6333
```

---

### GUERRA ELETRÔNICA (EW) & ÁUDIO

#### `status`
Relatório de hardware e módulos ativos.

```
hefestos@base:~# status

[ DIAGNOSTICO DE HARDWARE ]
- Cripto AES-128       : [ ONLINE ]
- HMAC-SHA256 Auth     : [ ONLINE ]
- Rastreio LoRa        : [ ONLINE ] (915 MHz | -75 dBm)
- Modulo Escuta        : [ ONLINE ] (FM 100.1)
```

#### `tune <BANDA> <FREQUENCIA>`
Sintoniza o rádio para uma banda e frequência específica.

**Bandas suportadas:**
- `FM` - VHF FM (88.0 - 108.0 MHz)
- `AM` - Médio (520 - 1710 kHz)
- `SW` - Onda Curta (2.3 - 30 MHz)

**Exemplos:**
```
hefestos@base:~# tune FM 100.1
[!] FM 100.1 MHz

hefestos@base:~# tune AM 800
[!] AM 800 kHz

hefestos@base:~# tune SW 6.1
[!] SW 6.1 MHz
```

---

### SISTEMA

#### `clear`
Limpa a saída visual do terminal.

```
hefestos@base:~# clear
```

#### `exit`
Encerra a conexão Telnet e desconecta.

```
hefestos@base:~# exit
Sessao encerrada.
```

#### `help`
Lista todos os comandos e sinopse.

```
hefestos@base:~# help

[ HEFESTOS SIGINT v2.0 KERNEL ]
-- TELEMETRIA --
  target   : Exibe coordenadas decodificadas
  map      : Gera link satelital de rastreamento
-- SIGINT --
  sniff    : Ultimo pacote interceptado
  history  : Buffer de interceptacoes
-- GUERRA ELETRONICA --
  status   : Relatorio de hardware
  tune     : Sintaxe: tune <BANDA> <FREQ>
-- SISTEMA --
  clear    : Limpa tela
  exit     : Desconecta
```

---

## 📊 Dashboard Web

### Layout

```
┌─────────────────────────────────────────┐
│     [ HEFESTOS SIGINT v2.0 ]            │
├─────────────────────────────────────────┤
│                                         │
│ [+] Status Operacional                  │
│ RX: 1234 | Auth Fails: 2                │
│ Alvo: ID:ALVO_01|Lat:...|Lon:...        │
│ RSSI: -75 dBm  ██████░░░░               │
│ [MAPEAR COORDENADAS]                    │
│                                         │
├─────────────────────────────────────────┤
│                                         │
│ [!] Sniffer RF (RAW)                    │
│ ┌─────────────────────────────────┐    │
│ │ [SINAL -75dBm] Raw data...      │    │
│ │ [SINAL -80dBm] Raw data...      │    │
│ │ [SINAL -70dBm] Raw data...      │    │
│ └─────────────────────────────────┘    │
│                                         │
├─────────────────────────────────────────┤
│                                         │
│ [*] Interceptacao Analisador Audio      │
│ [ FM       ] [ 100.1    ]               │
│ [ AM       ] [ 500      ]               │
│ [ SW       ] [ 6.1      ]               │
│ [SINTONIZAR ALVO]                       │
│ Escuta: FM 100.1                        │
│                                         │
└─────────────────────────────────────────┘
```

### Endpoints HTTP

#### GET `/`
Retorna dashboard HTML/CSS/JS.

#### GET `/dados`
Retorna JSON com status atual.

```json
{
  "mensagem": "ID:ALVO_01|Lat:-23.5505|Lon:-46.6333",
  "rssi": -75,
  "log": "[RX -75dBm] <span class='alert'>...</span><br>...",
  "rx_count": 1234,
  "auth_fails": 2
}
```

#### GET `/sintonizar?b=<BANDA>&f=<FREQ>`
Sintoniza rádio remotamente.

```
GET /sintonizar?b=FM&f=100.5
Resposta: OK
```

---

## 🔍 Formato de Dados

### Pacotes LoRa (Node1 → Node2)

```
Formato: ID:ALVO_01|Lat:<LAT>|Lon:<LON>|[HMAC_SIGNATURE]

Exemplo:
ID:ALVO_01|Lat:-23.5505|Lon:-46.6333|[8-byte signature]

Campos:
- ID: Identificador do alvo (ALVO_01 para confirmação)
- Lat: Latitude (6 casas decimais)
- Lon: Longitude (6 casas decimais)
- HMAC: Assinatura HMAC-8 para integridade
```

### Arquivo CSV (Node3 - SD Card)

```csv
TEMPO_MS,TIPO,DADOS
1000,ALVO_CONFIRMADO,ID:ALVO_01|Lat:-23.5505|Lon:-46.6333
2500,SNIFFER_RAW,\x48\x65\x66\x65\x73\x74\x6F\x73...
3100,ALVO_CONFIRMADO,ID:ALVO_01|Lat:-23.5510|Lon:-46.6335
4200,SNIFFER_RAW,BEACON|Type:Unknown
```

---

## ⚙️ Configuração Avançada

### Alterar Chave AES (Segurança Crítica)

**Conectar ao Node2 via Serial Monitor ou Telnet:**

```cpp
// Código C++ a executar em setup() de Node1 e Node2
ConfigManager config;
config.begin();

byte new_key[16] = {
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};
config.setAESKey(new_key, 16);
```

**Ou usar ferramenta de configuração (TODO):**
```
config_tool --device /dev/ttyUSB0 --set-aes-key "nova_chave_32_hex"
```

### Ativar Modo Debug

**Em compile time:**
```bash
arduino-cli compile -b esp32:esp32:esp32 -D DEBUG_MODE=1 src/Node2_Base_Hefestos/
```

**Ou em setup():**
```cpp
debug.enable();
debug.logf("Sistema iniciando com debug LIGADO");
```

### Alterar Intervalo GPS

**Node1 - Node1_Transmissor_Alvo.ino:**

```cpp
#define GPS_POLL_INTERVAL 1000  // Padrão: 1000ms
// Alterar para 500ms (mais rápido) ou 2000ms (economia bateria)
```

---

## 🔔 Indicadores Visuais

### LED Node3

| LED | Evento | Significado |
|-----|--------|-------------|
| 🟢 Verde | Piscada | Alvo confirmado (ID:ALVO_01) |
| 🔴 Vermelho | Piscada rápida | Tráfego desconhecido |
| 🔊 Buzzer | 2000Hz | Alvo detectado |

### Dashboard

| Status | Indicador |
|--------|-----------|
| Online | Barra RSSI verde |
| Offline | Barra RSSI cinza |
| Alvo Válido | Mensagem formatada |
| Alvo Inválido | "Aguardando sincronizacao..." |

---

## 🛡️ Segurança em Operação

### Credenciais Padrão (ALTERAR EM PRODUÇÃO)

```
WiFi SSID: Hefestos-SIGINT
WiFi Pass: Hefestos2024!SecureNet

Telnet User: admin
Telnet Pass: HefestosTactical@2024
```

### Proteção Contra Ataques

| Ataque | Mitigação |
|--------|-----------|
| Brute-force Telnet | 3 tentativas máximas + 100ms cooldown |
| DoS CLI | Rate limit 30 cmd/minuto |
| Pacotes forjados | HMAC-8 verificação em RX |
| Tamper SD | CRC16 em frames UART |
| MiTM WiFi | WPA2-PSK (password strength) |

---

## 📈 Monitoramento

### Métricas em Tempo Real

**Via Dashboard:**
- `RX`: Número de pacotes recebidos
- `Auth Fails`: Tentativas falhadas de autenticação
- `RSSI`: Força do sinal LoRa (dBm)

**Via Serial Monitor (Node3):**
```
[+] ALVO_TX: Lat:-23.5505|Lon:-46.6333
    Bytes: 35 | SD: OK
    Total: 1234 | Failed: 2
```

### Health Checks

**Verificar saúde Node2:**
```
hefestos@base:~# status
```

**Verificar SD Card Node3:**
```
Serial Monitor mostrará:
SD Card initialized OK  (ou)
SD Card FAILED - using RAM buffer only
```

---

## 🚨 Recuperação de Falhas

### Cenário: SD Card falha

**Detecção Automática:**
1. Node3 tenta 3 vezes inicializar
2. Se falhar, muda para fallback RAM buffer
3. A cada 30s, tenta reinicializar
4. Quando volta, sincroniza dados

**Verificação Manual:**
```
Serial Node3: [ERROR] SD Card FAILED - using RAM buffer only
              RAM buffer: 45/50 slots
```

### Cenário: Perda de Autenticação

**Telnet rejeitado após 3 tentativas:**
```
[!] Limite de tentativas excedido. Conexao encerrada.
```

**Solução:**
1. Reconectar (nova conexão = novo contador)
2. Usar credenciais corretas:
   - user: `admin`
   - pass: `HefestosTactical@2024`
3. Se esqueceu, resetar via factoryReset()

---

## 📞 Suporte e Troubleshooting

### Serial Monitor Output Esperado

**Node1 (GPS Transmitter):**
```
Node1: Inicializando...
[HEX] AES Key: 48 65 66 65 73 74 6F 73 54 61 63 74 69 63 61 00
Node1: Pronto para transmissao
TX Packet #1: -23.550500 (HMAC OK)
```

**Node2 (Base Station):**
```
Node2: Inicializando servidor base...
[HEX] AES Key loaded: 48 65 66 65 73 74 6F 73 54 61 63 74 69 63 61 00
WiFi SSID: Hefestos-SIGINT | Clients Max: 4
Node2: Ready
RX Packet #1 | RSSI: -75 | Auth: OK
```

**Node3 (Forense Logger):**
```
HEFESTOS - DATA LOGGER FORENSE v2.0
CRC16 + Error Recovery + RAM Fallback
SD Card initialized OK
Node3: Pronto para receber dados
[+] ALVO_TX: Lat:-23.5505|Lon:-46.6333
```

---

## 📝 Changelog v2.1

### Novidades v2.1
- ✅ HMAC-SHA256 Real via mbedtls
- ✅ Verificação HMAC em Node2
- ✅ Geração automática de chaves AES únicas
- ✅ Geração automática de senhas WiFi/CLI
- ✅ GPS Validation (só transmite se válido)
- ✅ Serial Protocol CRC completo
- ✅ RAM Buffer Flush quando SD retorna

### Novidades v2.0 (mantidas)
- ✅ EEPROM Configuration Manager
- ✅ Autenticação Telnet CLI 2FA
- ✅ CRC16 em UART (Node2↔Node3)
- ✅ Rate Limiter (DoS protection)
- ✅ SD Card Error Recovery + RAM Fallback
- ✅ Debug Mode compilável
- ✅ GPS Poll reduzido (3s → 1s)
- ✅ Código modularizado em headers

### Compatibilidade
- Node1: ESP32 (qualquer versão)
- Node2: ESP32 (qualquer versão)
- Node3: Arduino Uno/Mega/Nano

### Próximas Versões
- v2.2: WebSocket dashboard em tempo real
- v2.3: Suporte múltiplos alvos
- v2.4: Compressão gzip em buffer circular

---

**Versão**: 2.1.0  
**Data**: 2026-04-01  
**Suporte**: https://github.com/Alexandre200-lab/Hefestos-SIGINT/issues
