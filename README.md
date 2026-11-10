# Hefestos SIGINT — v5.0.0

Sistema de rastreamento e monitoramento de espectro em três nós ESP32, com link
LoRa autenticado (AES-256-GCM), base com dashboard HTTP autenticado (senha + TOTP)
e caixa-preta forense com log encadeado por hash em cartão SD.

> **Escopo e uso legal.** Este projeto é **passivo e defensivo**: recebe
> telemetria própria e mede espectro de radiodifusão. Ele **não** implementa
> jamming, spoofing, interceptação de terceiros, quebra de criptografia ou
> qualquer forma de exploração. Transmitir em frequências reguladas sem
> autorização é ilegal na maioria das jurisdições. O operador é o único
> responsável pelo uso e pelas licenças (ex.: Anatel no Brasil, FCC nos EUA).
> Use apenas em equipamentos e frequências que você está autorizado a operar.

---

## 1. Arquitetura

```
   ┌────────────────────┐        LoRa 915 MHz         ┌────────────────────┐
   │ NODE 1             │  frames binários AEAD       │ NODE 2             │
   │ Alvo / Emissor     │ ──────────────────────────► │ Base / Sensores    │
   │ ESP32-WROOM-32     │ ◄────────────────────────── │ ESP32-WROOM-32     │
   │ GPS + LoRa + Si4713│      TRACK_ACK autenticado  │ LoRa + Si4735 + AP │
   └────────────────────┘                             └─────────┬──────────┘
                                                               │ UART2 115200
                                                               │ frames c/ CRC16
                                                     ┌─────────▼──────────┐
                                                     │ NODE 3             │
                                                     │ Caixa Preta        │
                                                     │ ESP32-C3 + SD      │
                                                     │ log com hash chain │
                                                     └────────────────────┘
```

- **Node 1** transmite posição/qualidade do fix GNSS e nível de bateria.
- **Node 2** autentica, mantém estado por par, sincroniza o relógio UTC pelo
  epoch do GNSS, responde ACK, encaminha tudo ao Node 3, controla o receptor
  Si4735 (FM/AM/SW), executa varredura de espectro e detecção de interferência.
- **Node 3** grava um log append-only com cadeia de SHA-256 e responde a
  consultas de capturas/exportação.

O dashboard do Node 2 é servido em `http://<ip-do-node2>/` (SoftAP
`HEFESTOS-<node_id>` por padrão, ou STA se configurado).

---

## 2. O que mudou da v4.1 para a v5.0.0

A v4.1 não compilava e tinha falhas que invalidavam as propriedades de segurança
anunciadas. A v5.0.0 foi uma reescrita com verificação empírica.

### 2.1 Build

| Problema na v4.1 | Correção na v5.0.0 |
|---|---|
| `#include "../lib/..."` quebrava o build (o Arduino copia o sketch para outro diretório) | Biblioteca real em `lib/` com `library.properties`; build com `--libraries <raiz>` |
| `SD.begin()` com assinatura inexistente no core ESP32 | `SPI.begin(sck, miso, mosi, cs)` + `SD.begin(cs, SPI, 10 MHz)` |
| `SI4735::setBand()` não existe | `HefRadio` usa `setFM`/`setAM`/`setFrequency` |
| `LoRa.onReceive` com assinatura errada e `readBytes` inexistente | RX explícito via `parsePacket()`/`readBytes()` |
| Core não fixado; APIs mbedtls 2.x vs 3.x | Core fixado em **esp32 2.0.17** e APIs mbedtls 2.x |

Resultado medido: Node 1 **24%**, Node 2 **66%**, Node 3 **25%** da flash.

### 2.2 Criptografia e protocolo

| Falha na v4.1 | Correção na v5.0.0 |
|---|---|
| `decryptConfig()` comparava 116 bytes com 508 → **sempre falhava**; segredos ficavam em texto puro e a chave AES era regenerada a cada boot | Vault em NVS com header `magic/version/flags/totalLen/iv`, payload TLV cifrado e tamanho autenticado |
| Cada nó derivava a chave do **próprio MAC** → Node 1 e Node 2 nunca compartilhavam chave | PSK de deploy + `HKDF-SHA256(PSK, salt=node_id)` → chave por nó, compartilhável |
| Link usava AES-128 embora a documentação dissesse AES-256 | **AES-256-GCM** de fato |
| Nonce aleatório de 4 bytes + SHA-256 “para embaralhar” | Nonce determinístico `node_id(4) ‖ contador(8)`, único por (chave, emissor, contador) |
| Cabeçalho não autenticado | Cabeçalho de 15 bytes é o **AAD** do GCM |
| `RESYNC` aceitava qualquer contador fora da janela de 256 → replay de captura SDR | Anti-replay estrito: `contador <= maior` é sempre `REPLAY`; sem caminho de aceitação |
| `isRNGReady()` contava bytes não-nulos (passava com RNG quebrado) | Auto-teste diferencial do RNG, com falha fechada |
| Flags de versão colidiam com `FLAG_KEYS_GENERATED` | Layout de flags separado e explícito |
| PBKDF2 100k iterações sobre MAC de efuse | HKDF (primitiva correta para material de chave) |

### 2.3 Elétrica e RF

| Falha na v4.1 | Correção na v5.0.0 |
|---|---|
| Node 3: `SCK` e `LED_VERDE` ambos em **GPIO7** | SCK=4, MISO=5, MOSI=6, CS=10, LED verde=7, LED vermelho=1, buzzer=3 |
| Node 2: UART0 usada para o Node 3, matando o console | Node 3 em **UART2**; console em UART0 |
| Node 3: UART0 para o link, sem console | Link em **UART1**; console em UART0 |
| Node 1: GPS em UART0, conflitando com o console | GPS em **UART2**; console em UART0 |
| Pinos de strapping/flash usados no C3 | Conjunto validado por teste automatizado (sem GPIO2/8/9/12–17) |

### 2.4 ESM (espectro / jamming) — de decorativo para real

| Falha na v4.1 | Correção na v5.0.0 |
|---|---|
| Varredura usava `LoRa.readRSSI()` — reportava o RSSI do **LoRa** para toda banda | `HefRadio::readQuality()` usa `getCurrentReceivedSignalQuality()` do Si4735 (RSSI/SNR reais) |
| Varredura síncrona com `delay(50)`, receptor fora do ar, sem restaurar a sintonia do operador | Máquina de estados não-bloqueante (`SpectrumScanner::tick`), dwell configurável, restauração da frequência do operador |
| `monitorLinkQuality()` lia `markCounter()`, que nunca era chamado → sempre “NORMAL” | `JammingDetector` com RSSI/SNR reais dos pacotes, piso de ruído do Si4735 e perda de enlace |
| Node 2 nunca enviava nada ao Node 3 | Encaminhamento no loop principal, fila não-bloqueante, frames com CRC16 |
| Capturas processadas só dentro de handlers HTTP bloqueantes | RX/TX serial 100% no loop; handlers nunca bloqueiam |

### 2.5 Segurança operacional

| Falha na v4.1 | Correção na v5.0.0 |
|---|---|
| Telnet em texto claro | Removido; console local + HTTP autenticado |
| TOTP existia mas nunca era incluído/verificado | TOTP **obrigatório** no login, com proteção de replay por passo de 30 s |
| Sessões sem expiração real | Idle 15 min / absoluta 4 h, binding por IP, token de 32 bytes |
| Rate limit global bloqueava o próprio operador | Buckets por IP: login (5/min) e comandos (60/min, cooldown 50 ms) |
| Dashboard montava HTML com dados de RF | Dashboard usa `textContent` (sem `innerHTML`), cabeçalhos `nosniff`/`DENY`/`no-referrer` |
| Funções de debug podiam imprimir segredos | Nenhuma rotina imprime chave/senha/PSK |

---

## 3. Modelo de segurança

### 3.1 Ativos e adversários

Ativos: PSK de deploy, chaves de link derivadas, credenciais HTTP, segredo TOTP,
posições rastreadas e o log forense.

Adversários considerados:
- Observador de RF com SDR (captura e reenvio de frames).
- Atacante na rede local/Wi-Fi (força bruta de login, CSRF, XSS).
- Furto do cartão SD (integridade do log) e acesso físico ao console serial.

Fora de escopo: ataque com acesso físico completo ao ESP32 (extração de flash sem
secure boot), comprometimento do PSK por engenharia social, jamming ativo por
terceiros (detectamos, não emitimos).

### 3.2 Provisionamento de chaves

```
PSK (32 bytes, único do deployment)
        │
        ├── HKDF-SHA256(salt = node_id_1, info = "hefestos-v5/link/aes256") → key_1
        ├── HKDF-SHA256(salt = node_id_2, info = "hefestos-v5/link/aes256") → key_2
        └── HKDF-SHA256(salt = node_id_N, info = "hefestos-v5/link/aes256") → key_N
```

- O PSK é gravado uma única vez em cada nó pelo console serial.
- A chave de link **nunca** trafega.
- Comprometer um nó não expõe a chave de outro nó.
- Rotação: novo PSK em todos os nós + reinício. O Node 2 re-deriva as chaves dos
  pares ao receber o primeiro frame autenticado de cada `node_id`.

### 3.3 Vault de configuração (NVS)

```
+---------------------------+
| magic    u32              |  "HFFC"
| version  u8               |  5
| flags    u8               |
| totalLen u16              |  ciphertext + tag
| iv       u8[12]           |
| reservado u8[16]          |
+---------------------------+
| ciphertext || tag GCM     |  AES-256-GCM
+---------------------------+
```

- Chave do vault: `HKDF-SHA256(MAC do efuse, salt="Hefestos-v5-vault")`.
  O vault é **vinculado ao chip**: copiar a NVS para outro ESP32 invalida o
  conteúdo (anti-clonagem).
- Payload TLV: SSID/senha Wi-Fi, usuário/senha HTTP, segredo TOTP, PSK e
  enrollments (`node_id`, `key_id`).
- `totalLen` é validado contra o tamanho gravado: truncamento/corrupção falha
  fechado.
- Segredos ficam em cache em RAM somente após o boot e são apagados em
  `factoryReset()`.

### 3.4 Frame LoRa

Formato (big-endian), 15 bytes de cabeçalho + payload + tag:

| offset | tam | campo |
|---:|---:|---|
| 0 | 1 | `magic` = `0xA5` |
| 1 | 1 | `version` = 5 |
| 2 | 1 | `type` (`TRACK`, `TRACK_ACK`, …) |
| 3 | 1 | `flags` (status do track) |
| 4 | 1 | `keyId` |
| 5 | 2 | `nodeId` (16 bits do MAC) |
| 7 | 2 | `epoch` (novo a cada boot) |
| 9 | 4 | `counter` (monotônico estrito) |
| 13 | 2 | `payloadLen` |
| 15 | N | payload |
| 15+N | 16 | tag GCM |

- **AAD** = cabeçalho completo. Alterar `nodeId`, `epoch`, `counter` ou `type`
  invalida a tag.
- **Nonce** = `nodeId(4) ‖ counter(8)`.
- `nodeId` viaja em claro porque o receptor precisa dele para derivar a chave;
  autenticidade vem da tag. Um `nodeId` forjado produz tag inválida.
- Payload de tracking (23 bytes): `epochUtc`, `lat`, `lon`, `altM`, `speedCms`,
  `courseDeg`, `hdopX10`, `sats`, `fixQuality`, `batteryPct`, `statusFlags`.
- `TRACK_ACK` ecoa `epoch`/`counter` no cabeçalho e é cifrado com a chave do par,
  com prefixo de nonce = `nodeId` do par. Sem ACK válido, o Node 1 retransmite
  (mesmo contador; o Node 2 reenvia o ACK de duplicata sem reprocessar o track).

### 3.5 Anti-replay

`RxSequence` por par `(node_id)`:

- `counter <= maior_visto` → `REPLAY` (sempre rejeitado).
- `counter > maior + 1024` → `FAR` (rejeitado).
- `epoch` anterior → `STALE_EPOCH` (rejeitado).
- `epoch` novo → nova sessão do emissor, janela reiniciada.

A janela de 1024 bits serve apenas para **contar lacunas** (diagnóstico), nunca
para aceitar pacotes atrasados.

### 3.6 Autenticação HTTP

- Login: usuário + senha + **TOTP de 6 dígitos** (RFC 6238, SHA-1, 30 s).
- Comparações em tempo constante.
- Código TOTP já usado não é aceito novamente.
- Sessão: token de 32 bytes (hex), `HttpOnly`, `SameSite=Strict`, binding por IP,
  expiração idle e absoluta.
- Rate limit por IP e bloqueio de 30 min após 5 falhas.
- TOTP exige relógio sincronizado. O Node 2 sincroniza pelo epoch GNSS recebido
  ou pelo comando `settime <unix>` no console. Sem relógio válido, o login HTTP
  responde com erro explícito (o console serial continua disponível).

---

## 4. Protocolo serial Node 2 ↔ Node 3

```
START(0xAA) TYPE(1) SEQ(2) LEN(2) PAYLOAD(N) CRC16(2) END(0x55)
```

CRC16-IBM sobre `TYPE..PAYLOAD`. Tipos: `DATA`, `HEARTBEAT`, `REQUEST`,
`RESPONSE`, `TIME`, `ACK`. Requisições: `CAPTURE_LAST`, `CAPTURE_LIST`,
`CAPTURE_CLEAR`, `LOG_EXPORT`, `LOG_INFO`.

O Node 3 responde com `RESPONSE` cujo primeiro byte é o ID da requisição,
seguido de JSON. O Node 2 mantém um cache e nunca bloqueia o handler HTTP
esperando o Node 3.

---

## 5. Hardware e pinagem

### 5.1 Node 1 — Alvo / Emissor (ESP32-WROOM-32)

| Sinal | GPIO |
|---|---:|
| LoRa NSS | 5 |
| LoRa RESET | 14 |
| LoRa DIO0 | 26 |
| Si4713 RESET | 32 |
| I2C SDA | 21 |
| I2C SCL | 22 |
| GPS RX (do módulo) | 16 |
| GPS TX (para o módulo) | 17 |
| Chave RF | 25 |
| ADC bateria | 36 |
| Console | UART0 |

### 5.2 Node 2 — Base (ESP32-WROOM-32)

| Sinal | GPIO |
|---|---:|
| LoRa NSS | 5 |
| LoRa RESET | 14 |
| LoRa DIO0 | 26 |
| Si4735 RESET | 13 |
| I2C SDA | 21 |
| I2C SCL | 22 |
| UART2 TX → Node 3 RX | 17 |
| UART2 RX ← Node 3 TX | 16 |
| Console | UART0 |

### 5.3 Node 3 — Caixa Preta (ESP32-C3)

| Sinal | GPIO |
|---|---:|
| SD CS | 10 |
| SD MOSI | 6 |
| SD MISO | 5 |
| SD SCK | 4 |
| UART1 RX ← Node 2 TX | 0 |
| UART1 TX → Node 2 RX | 2 |
| LED verde | 7 |
| LED vermelho | 1 |
| Buzzer | 3 |
| Console | UART0 |

> O ESP32-C3 usa o barramento FSPI nativo nesses pinos. O console UART0 usa os
> pinos padrão 20/21, então o link com o Node 2 vai para GPIO0 (RX) e GPIO2 (TX).
> GPIO2 é pino de strapping (precisa estar alto no boot) e a linha TX ociosa já
> fica alta; recomenda-se pull-up externo de 10 kΩ. GPIO8/9 (strapping),
> GPIO12–17 (flash), GPIO18/19 (USB-JTAG) e GPIO20/21 (UART0) são evitados. O
> teste `test_functional.sh` falha se essa regra for violada.

---

## 6. Estrutura do repositório

```
lib/                     biblioteca compartilhada (Arduino library)
  library.properties
  src/
    hefestos_pins.h      pinagem, versão, constantes
    crypto_gcm.h         AES-256-GCM + HKDF-SHA256 + comparação constante
    config.h             vault NVS cifrado (TLV)
    provisioning.h       derivação de chave por nó
    secure_protocol.h    anti-replay (RxSequence/TxSequence)
    link_protocol.h      frame LoRa + payload de tracking
    serial_protocol.h    link Node2<->Node3 (CRC16)
    radio_si4735.h       wrapper do receptor
    spectrum.h           varredura não-bloqueante
    jamming_detector.h   detecção real de interferência
    field_log.h          log forense com hash chain
    totp_auth.h          TOTP RFC 6238
    rate_limiter.h       token buckets por IP
    debug.h              logging sem vazamento de segredos
src/
  Node1_Transmissor_Alvo/
  Node2_Base_Hefestos/
  Node3_Caixa_Preta_ESP32C3/
build.sh                 build dos 3 nós
test_functional.sh       invariantes + build
```

---

## 7. Build

Requisitos:

- `arduino-cli` (>= 0.35)
- core **esp32:esp32 2.0.17** (mbedtls 2.x)
- bibliotecas externas (versões testadas em `dependencias.txt`)

```bash
arduino-cli core install esp32:esp32@2.0.17
./build.sh
```

O `build.sh` valida a versão do core e compila os três sketches com
`--libraries <raiz>`, que é o que faz os includes `<config.h>` etc. resolverem.

Para gravar:

```bash
arduino-cli upload -p /dev/ttyUSB0 --fqbn esp32:esp32:esp32 \
  --input-dir build/node1 src/Node1_Transmissor_Alvo
# Node 3: --fqbn esp32:esp32:esp32c3
```

> Se o core 2.0.17 não estiver disponível no índice, instale-o pelo
> board manager com a URL do ESP32 e fixe a versão. A v5 **não** é compatível
> com o core 3.x sem ajustar as APIs de mbedtls.

---

## 8. Provisionamento

Faça em cada nó, pelo console serial (115200 8N1), na ordem abaixo.

1. **PSK de deployment** (uma vez, igual em todos os nós):

   ```bash
   # gere 32 bytes aleatórios, ex.: openssl rand -hex 32
   psk <64 caracteres hex>
   ```

2. **Wi-Fi do Node 2** (opcional; sem isso ele sobe SoftAP):

   ```bash
   wifi <ssid> <senha>
   ```

   No primeiro boot, o Node 2 imprime no console o SSID
   `HEFESTOS-<node_id>` e a senha WPA2 (derivada do MAC do chip).

3. **Credenciais HTTP**: no primeiro boot o Node 2 gera e imprime
   `admin` + senha aleatória. Troque:

   ```bash
   user <nome>
   pass <senha-com-10-ou-mais>
   ```

4. **TOTP**: o primeiro boot imprime o segredo base32 e a URI `otpauth://`.
   Cadastre no autenticador. Para reexibir: `totp`.

5. **Relógio**: o Node 2 sincroniza sozinho quando recebe um track com epoch
   GNSS válido. Antes disso (ou sem GPS), use:

   ```bash
   settime 1760000000
   ```

6. Reinicie os nós e confirme no console: `status` deve mostrar chave OK,
   relógio válido e pares autenticados após o primeiro track.

> **Nunca** versione o PSK, a senha do Wi-Fi, a senha HTTP ou o segredo TOTP.
> O repositório não contém nenhum desses valores.

---

## 9. Operação

### 9.1 Console serial

**Node 1:** `help`, `status`, `id`, `psk <hex>`, `psk show`,
`fm on|off`, `fm freq <kHz>`, `fm power <0-255>`.

**Node 2:** `help`, `status`, `id`, `psk`, `user`, `pass`, `totp`,
`wifi`, `settime`, `time`, `enroll <node> <keyid>`, `peers`,
`sweep on|off|now`, `radio <FM|AM|SW> <kHz>`, `reboot`, `factory`.

**Node 3:** `help`, `status`, `info`, `caps`, `clear`, `export`,
`time <unix>`, `format`, `reboot`.

### 9.2 API HTTP (Node 2)

Todas exigem sessão autenticada (cookie `HEF_SID`).

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | dashboard |
| GET/POST | `/login` | formulário e autenticação |
| POST | `/logout` | encerra a sessão |
| GET | `/api/status` | estado geral |
| GET | `/api/peers` | pares autenticados e último track |
| GET | `/api/radio` | banda, frequência e qualidade do Si4735 |
| POST | `/api/radio?band=FM&freq=100100` | sintoniza |
| GET | `/api/spectrum` | amostras da varredura |
| POST | `/api/sweep[?auto=1][&dwell=90]` | inicia varredura |
| GET | `/api/health` | heap, relógio, contadores |
| GET | `/api/captures` | capturas do Node 3 (cache) |
| GET | `/api/logs` | estado do log forense |

### 9.3 Varredura de espectro

Plano padrão: FM 87,5–108 MHz (passo 250 kHz), AM 520–1710 kHz (20 kHz),
SW 2,3–30 MHz (25 kHz). A varredura é incremental: um ponto por `tick()`,
com dwell configurável, e restaura a frequência do operador ao terminar.
`auto=1` repete continuamente.

### 9.4 Detecção de interferência

Estados: `NORMAL`, `DEGRADED` (SNR mediana abaixo do limite),
`NOISE_RISE` (piso de ruído do Si4735 subiu mais de 10 dB por 30 s) e
`LINK_LOSS` (nenhum frame LoRa há 15 s). As métricas vêm do RF real —
não de contadores que nunca eram atualizados.

---

## 10. Log forense (Node 3)

- Registro binário append-only: `seq`, `utc`, `type`, `len`, `data`.
- Cadeia: `hash[n] = SHA256(hash[n-1] ‖ registro[n])`.
- Cabeçalho do arquivo semeia a cadeia com o `node_id` (dois gravadores nunca
  produzem a mesma cadeia).
- `export` gera `HEFLOG.JSONL` + `HEFLOG.HASH` com contagem, hash final e
  resultado da verificação de integridade.
- Ao reiniciar, o Node 3 varre o arquivo e retoma `seq`/`records`/cabeça da
  cadeia sem reiniciar a numeração.
- O cartão SD **não** é cifrado em repouso: a cadeia detecta alteração, mas não
  impede leitura. Proteja fisicamente o cartão.

---

## 11. Testes

```bash
./test_functional.sh            # invariantes + build dos 3 nós
./test_functional.sh --no-build # só invariantes (rápido, sem toolchain)
```

Cobertura: pinagem duplicada, pinos proibidos no C3, layout do frame,
anti-replay estrito, ausência de Telnet/EEPROM/include relativo, TOTP no login,
dashboard sem injeção de HTML e ausência de chaves hardcoded.

---

## 12. Solução de problemas

| Sintoma | Causa provável | Ação |
|---|---|---|
| `chave de link: AUSENTE` | PSK não gravado | `psk <64 hex>` e reiniciar |
| Node 2 não autentica tracks | PSK diferente entre nós | regravar o mesmo PSK |
| Login recusa TOTP | relógio não sincronizado | `settime <unix>` ou aguardar GNSS |
| `/api/spectrum` vazio | varredura não iniciada | `POST /api/sweep` ou `sweep now` |
| Node 3 sem log | SD ausente/incompatível | verificar 3,3 V, cartão FAT32, `status` |
| Node 2 reinicia sozinho | heap crítico | reduzir sessões/varredura; ver `/api/health` |
| Frame rejeitado como replay | emissor reiniciou sem novo epoch | reiniciar o Node 1 (epoch novo) |

---

## 13. Rotação de chaves e reset

- **Rotação de PSK:** grave o novo PSK em todos os nós (`psk ...`), reinicie.
  O Node 2 re-deriva a chave de cada par no primeiro frame válido.
- **Reset de fábrica (Node 2):** `factory` apaga PSK, enrollments, credenciais
  e TOTP. O chip continua o mesmo (a chave do vault é derivada do MAC).
- **Node 3:** `format` apaga o log e recria o cabeçalho. Isso **destrói** a
  cadeia anterior; exporte antes.

---

## 14. Limitações conhecidas

- O link LoRa é ponto-a-ponto; não há roteamento multi-salto.
- A hora do Node 1 vem do GNSS; sem fix válido, o campo `epochUtc` é 0 e o
  Node 2 não sincroniza por ele.
- A varredura usa um único Si4735: mede uma frequência por vez.
- `NOISE_RISE` é heurístico (limiar de 10 dB / 30 s), não um classificador.
- Secure boot e flash encryption **não** são habilitados pelo firmware; recomenda-
  se habilitá-los no processo de produção (e isso queimará eFuses de forma
  irreversível).
- O SoftAP deriva a senha do MAC do chip. Quem tiver acesso físico ao console
  serial vê a senha — trate o console como interface privilegiada.

---

## 15. Licença

Ver `LICENSE`. Uso sujeito às leis de telecomunicações aplicáveis.
