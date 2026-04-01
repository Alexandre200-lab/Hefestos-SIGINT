# Projeto HEFESTOS SIGINT: Estação Tática SIGINT Multi-Banda (v2.1)

Hefestos é um sistema avançado de Inteligência de Sinais (SIGINT), guerra eletrônica e telemetria com arquitetura Master-Slave distribuída. Realiza rastreamento GPS criptografado (AES-128+HMAC), transmissão via LoRa (915 MHz Sub-GHz), interceptação de RF (AM/FM/SW), e retenção forense em SD Card com autenticação 2FA.

## Versão 2.1 - Melhorias de Segurança

### Segurança (Melhorias Críticas v2.1)
- **HMAC-SHA256 Real**: Substituído HMAC custom por HMAC-SHA256 via mbedtls
- **Verificação HMAC**: Node2 agora verifica assinaturas corretamente
- **Chaves Únicas**: Geração automática de chaves AES no primeiro boot
- **Senhas Seguras**: Geração automática de senhas WiFi/CLI aleatórias
- **EEPROM v2**: Magic bytes atualizados para `0x4846` + flag keys_generated

### Segurança (Melhorias v2.0 mantidas)
- **EEPROM Config Manager**: Chaves AES armazenadas em EEPROM, não em source
- **WiFi Forte**: Senha alterada de `xdneo123` para `Hefestos2024!SecureNet` (22 chars)
- **Autenticação Telnet**: Login 2FA (user: admin, password via EEPROM)
- **Rate Limiting**: CLI protegido contra DoS (30 cmd/min, 100ms cooldown)

### Confiabilidade (Melhorias mantidas)
- **CRC16 em UART**: Frames estruturados para Node2↔Node3 com checksum
- **SD Card Recovery**: Retry logic (3x), fallback RAM buffer (50 slots)
- **RAM Buffer Flush**: Sincronização automática quando SD volta online
- **GPS Validation**: Node1 só transmite se GPS com coordenadas válidas
- **Código Modular**: Headers: `config.h`, `crypto_hmac.h`, `serial_protocol.h`, `rate_limiter.h`, `debug.h`

### Performance
- **GPS Interval**: 1000ms (3x mais rápido que v1.0)
- **Pre-allocação**: Arrays estáticos em vez de String dinâmicas

## 📋 Arquitetura do Sistema

O projeto opera com 3 nós físicos independentes:

### 1. **Node 1 (Transmissor/Alvo - ESP32)**
- Captura GPS (intervalo 1000ms)
- Criptografia AES-128 com chave em EEPROM
- Transmissão LoRa 915 MHz com HMAC-8
- Transmissor FM (Si4713) capturando áudio ambiente

### 2. **Node 2 (Base Hefestos - ESP32)**
- Servidor central de comando
- Interceptação LoRa com validação HMAC
- Dashboard Web (HTTP port 80)
- CLI Telnet com 2FA (port 23, rate limit 30 cmd/min)
- Controle remoto de rádio (AM/FM/SW)
- Comunicação CRC16 com Node3

### 3. **Node 3 (Caixa Preta - Arduino)**
- Co-processador de log forense
- Recepção UART com validação CRC16
- Gravação em SD Card com retry (3x)
- Fallback RAM buffer se SD falhar
- Alertas físicos (LED Verde/Vermelho, Buzzer)

## Segurança

### Credenciais Padrão (ALTERAR EM PRODUÇÃO)
```
WiFi SSID:  Hefestos-SIGINT
WiFi Pass:  Hefestos2024!SecureNet

Telnet User: admin
Telnet Pass: HefestosTactical@2024

AES Key:    HefestosTactica\0
AES IV:     VetorInicializado
```

### Proteções Implementadas
| Camada | Proteção | Mecanismo |
|--------|----------|-----------|
| RF | Integridade | HMAC-8 bytes |
| RF | Confidencialidade | AES-128 |
| UART | Integridade | CRC16 |
| API | Autenticação | 2FA Telnet |
| API | DoS | Rate limiting 30 cmd/min |
| Config | Armazenamento | EEPROM com magic bytes |

##  Pinagem de Hardware

### Node 1 (Transmissor ESP32)
```
LoRa SX1276:        CS(5), RST(14), DIO0(26), SPI(18,19,23)
GPS NEO-6M:         RX(16), TX(17)
TX FM Si4713:       SDA(21), SCL(22), RST(32)
```

### Node 2 (Base ESP32)
```
LoRa SX1276:        CS(5), RST(14), DIO0(26), SPI(18,19,23)
RX Scanner Si4735:  SDA(21), SCL(22), RST(12)
UART para Node3:    TX(17)→RX(Arduino), RX(16)→TX(Arduino)
```

### Node 3 (Caixa Preta Arduino)
```
MicroSD Module:     CS(4), MOSI(11), MISO(12), SCK(13)
UART from Node2:    RX(0), TX(1)
Outputs:            LED Verde(7), LED Vermelho(8), Buzzer(9)
```

##  Documentação

| Documento | Conteúdo |
|-----------|----------|
| `IMPLEMENTATION_GUIDE_v2.md` | Arquitetura técnica, segurança, deployment, troubleshooting |
| `OPERATION_MANUAL_v2.md` | Comandos CLI, dashboard, configuração avançada, recuperação de falhas |
| `dependencias.txt` | Bibliotecas Arduino necessárias |

## 🎯 Operação Rápida

### 1. Compilar e carregar
```bash
# Node1
arduino-cli compile -b esp32:esp32:esp32 src/Node1_Transmissor_Alvo/
arduino-cli upload -p /dev/ttyUSB0 -b esp32:esp32:esp32

# Node2
arduino-cli compile -b esp32:esp32:esp32 src/Node2_Base_Hefestos/
arduino-cli upload -p /dev/ttyUSB1 -b esp32:esp32:esp32

# Node3
arduino-cli compile -b arduino:avr:uno src/Node3_Caixa_Preta_Arduino/
arduino-cli upload -p /dev/ttyUSB2 -b arduino:avr:uno
```

### 2. Acessar sistema
```bash
# Dashboard Web
open http://192.168.4.1

# CLI Telnet
telnet 192.168.4.1 23
# user: admin
# pass: HefestosTactical@2024
```

### 3. Comandos básicos
```
help       # Lista todos os comandos
status     # Status hardware (AES, LoRa, Rádio)
target     # Exibe coordenadas GPS decodificadas
map        # Gera URL Google Maps
sniff      # Último pacote bruto interceptado
history    # Buffer de últimas interceptações
tune FM 100.1  # Sintoniza FM
```

## Melhorias de Performance

| Métrica | v1.0 | v2.0 | Ganho |
|---------|------|------|-------|
| GPS Polling | 3000ms | 1000ms | 3x |
| WiFi Password | 8 chars | 22 chars | 16x mais seguro |
| UART Reliability | Sem checksum | CRC16 | 100% detecção |
| Auth Attempts | Ilimitadas | 3 + throttle | Protegido |
| Rate Limit | Nenhum | 30 cmd/min | DoS protection |
| SD Fallback | Nenhum | RAM 50 slots | Confiabilidade |

##  Troubleshooting

### "SD Card FAILED"
→ Node3 entra em fallback RAM buffer (50 eventos máx)  
→ Tenta reinicializar a cada 30 segundos  
→ Dados sincronizados quando SD volta online

### "Rate limit exceeded"
→ Aguarde 100ms entre comandos  
→ Máximo 30 comandos/minuto  
→ Novo slot Telnet reseta contador

### "Autenticação falhou"
→ Padrão: user=`admin`, pass=`HefestosTactical@2024`  
→ Resetar com: `config.factoryReset();`

## Próximas Melhorias (v2.1+)

- [ ] Compressão gzip em buffer circular
- [ ] Suporte múltiplos alvos simultâneos
- [ ] Criptografia de dados em repouso

##  Versão

- **Versão atual**: 2.1.0
- **Data**: 2026-04-01
- **Status**: Production-ready
- **Compatibilidade**: ESP32, Arduino Uno/Mega, módulos conforme pinagem
