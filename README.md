# Hefestos SIGINT — v5.1.0

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

## 0. v5.1.0 — anti-replay sobrevivente a reinício + RF viável

Os primeiros quatro itens do plano de escala militar:

1. **O anti-replay agora sobrevive a um reinício do receptor** (item 1.1) —
   um frame capturado por SDR não é mais aceito como frame novo depois que
   o receptor reinicia.
2. **O link LoRa passa a ser fisicamente viável** (item 1.2) — a v5.0.0
   operava com 221,6% de duty cycle, o que é impossível.
3. **A transmissão passa a ser adaptativa** (item 1.3) — por evento
   (movimento) ou por heartbeat, em vez de periódica.
4. **O dispositivo sabe por que reiniciou** (item 1.4) — contadores de
   brownout/WDT/panic persistidos, watchdog de tarefa sobre o loop
   principal, e reinício controlado com o motivo registrado.

> Os percentuais de duty cycle desta tabela mantêm o ACK atual (33 B) nos
> dois lados, para isolar o efeito da mudança de SF e de intervalo. O
> firmware v5.0.0 usava um ACK de 35 B: com ele, eram **225,7%** e
> **6,50 Ah/dia**. Ver [§9.5.2](#952-configuração-adotada).

| v5.0.0 | v5.1.0 |
|---|---|
| Estado anti-replay | só em RAM | **persistido no vault cifrado** (TLV `0x0A`) |
| Frame capturado, replay após reinício | **aceito** | **rejeitado** (`REPLAY` / `STALE_EPOCH`) |
| Queda longa de link | enlace morria (`FAR`) | reancora o high-water |
| SF10 a 1 Hz → **221,6% de duty cycle** (inviável) | **SF8 a 1/30 s → 1,85%** |
| Nenhuma verificação de conformidade de RF | **perfis regionais + firmware impede violar o duty cycle** |
| TX **periódica** (1 frame/30 s) | **adaptativa**: movimento > 10 m ou heartbeat 60 s |
| Até 3 transmissões por evento | **no máximo 2** (1 + 1 retry) |
| ACK de 35 B (payload redundante) | **33 B** (flags + RSSI de retorno) |
| Beacon FM contínuo | **duty cycle próprio (10%) + corte automático < 20% de bateria** |
| Causa do reinício | **não registrada** (indistinguível de um brownout) | **contadores NVS: boots/brownouts/wdt/sw/panic** |
| Watchdog do loop principal | **inexistente** (travamento silencioso) | **TWDT de 30 s + progresso nas operações longas** |
| Reinício por comando | `ESP.restart()` cru (reinício cego) | **`hefRestart()` grava a intenção antes de sair** |
| Gravação do estado | — | imediata no epoch novo; 60 s para o contador |
| Testes | 7 grupos | 11 grupos (548 verificações no host; +515 sobre a v5.0.0) |

Detalhes em [§3.5.1](#351-estado-persistido-replay-pós-reboot--v510),
[§9.5](#95-orçamento-de-rf-e-conformidade-regulatória),
[§9.6](#96-política-de-tx-adaptativa-node-1) e
[§9.7](#97-watchdog-brownout-e-causa-de-reinício-node-2--node-3--v510).

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

## 2. O que mudou da v4.1 para a v5.1.0

A v4.1 não compilava e tinha falhas que invalidavam as propriedades de segurança
anunciadas. A v5.0.0 foi uma reescrita com verificação empírica; a v5.1.0
corrige a segurança do enlace e a viabilidade física do link RF (ver §0).

### 2.1 Build

| Problema na v4.1 | Correção na v5.0.0/v5.1.0 |
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

**RF (v5.1.0):** o link LoRa da v5.0.0 operava com **SF10 a 1 frame/s**, o
que exige **225,7% de duty cycle** — fisicamente impossível, com 6,5 Ah/dia
só de TX. Agora são **SF8 a 1/30 s** (duty cycle 1,88%, 0,054 Ah/dia), com
jitter de ±10%, perfis regionais de referência e **impedimento no firmware**
de qualquer transmissão que viole o limite. Ver [§9.5](#95-orçamento-de-rf-e-conformidade-regulatória).

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

### 2.6 Operação em campo (v5.1.0)

| Falha na v5.0.0 | Correção na v5.1.0 |
|---|---|
| Nenhuma registro da causa do reinício: brownout e travamento de software eram indistinguíveis | Contadores NVS por classe (`boots`/`brownouts`/`wdt`/`sw`/`panics`) + causa exata do último boot |
| Nenhum watchdog sobre o `loop()`: um travamento deixava o aparelho "vivo" mas inútil, em silêncio | TWDT de 30 s inscrito na task do loop; reinício com causa `wdt-tarefa` |
| Operações longas (cadeia do SD, exportação, gravação do vault) sem progressão: reinício falso ou travamento mascarado | Callback de progresso por ponto de avanço real; o guarda é uma **consulta**, e código travado não o chama |
| `ESP.restart()` cru: reinício cego, sem motivo | `hefRestart()` grava a intenção antes de sair; nenhum reinício cru restou |
| Contadores gravados a cada boot: 438 mil escritas/ano num laço de brownout | Guarda de desgaste: grava na mudança de causa ou a cada 10 boots; flush periódico de 5 min |
| Estado do watchdog nunca exposto | `watchdog_active` + `watchdog_timeout_s` na API e no console — **honestos**: timeout desconhecido é `0`, nunca estimado |

Ver [§9.7](#97-watchdog-brownout-e-causa-de-reinício-node-2--node-3--v510).

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
- `counter > maior + 65536` → `FAR` (rejeitado, falha fechada).
- `epoch` anterior → `STALE_EPOCH` (rejeitado).
- `epoch` novo → nova sessão do emissor, janela reiniciada.

A janela de 1024 bits (`HEF_COUNTER_WINDOW`) serve apenas para **contar
lacunas** (diagnóstico), nunca para aceitar pacotes atrasados. Saltos maiores
que a janela, mas menores que `HEF_COUNTER_MAX_GAP` (65536), reancoram o
high-water: são frames legítimos de um enlace que ficou horas sem receptionar.
Acima de `HEF_COUNTER_MAX_GAP` o frame é rejeitado e o enlace só ressincroniza
com um `epoch` novo (emissor reiniciado).

#### 3.5.1 Estado persistido (replay pós-reboot) — v5.1.0

Até a v5.0.0 o estado anti-replay vivia **apenas em RAM**. Um frame capturado
por SDR — com tag GCM legítima, portanto criptograficamente autenticado — era
**aceito como frame novo** depois que o receptor reiniciava, porque o par
recomeçava sem `epoch`/contador. O replay passava por todas as verificações.

Agora o Node 2 persiste o estado por par no **vault cifrado** (TLV
`HEF_TLV_PEER_STATE`, `0x0A`):

| campo | tam | descrição |
|---|---:|---|
| `node_id` | u16 LE | par |
| `epoch` | u16 LE | sessão conhecida do emissor |
| `counter` | u32 LE | high-water aceito |

No boot, `restorePeerStates()` reconstrói os pares a partir dos enrollments
persistidos (a chave de cada par é derivada de forma determinística do PSK de
deploy + `node_id`) e hidrata o estado com `RxSequence::hydrate()`. Resultado:

- frame capturado **do epoch anterior** → `STALE_EPOCH` (rejeitado);
- frame capturado **do epoch atual** → `REPLAY` (rejeitado).

**Política de gravação:**

| evento | gravação |
|---|---|
| epoch novo (emissor reiniciou) ou primeiro contato | **imediata** |
| contador avançou | a cada `HEF_PEER_STATE_FLUSH_MS` (60 s) |

O intervalo de 60 s é o **limite do risco residual**: após um reinício, um
replay de frame do *mesmo* epoch com contador até 60 s atrás ainda pode ser
aceito. Replay de epoch anterior é sempre rejeitado. O custo é de ~1440
escritas/dia no NVS (~6 anos de endurance com o wear-leveling do ESP32).

Indicadores no console e em `/api/peers`: `stale_epoch` (replays pós-reboot
bloqueados) e `resyncs` (reancoragens por salto grande — evento de segurança
relevante, pode indicar captura/replay de frame distante).

> **Migração de um vault v5.0.0:** pares enrolled sem estado persistido são
> aceitos por TOFU no primeiro frame válido e passam a ser persistidos. A
> partir daí a proteção é integral.

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

| offset | tam | campo |
|---:|---:|---|
| 0 | 1 | `START` = `0xAA` |
| 1 | 1 | tipo |
| 2 | 2 | sequência (big-endian) |
| 4 | 2 | comprimento do payload (big-endian) |
| 6 | N | payload (pode conter `0xAA`/`0x55` à vontade) |
| 6+N | 2 | CRC16-IBM sobre `TYPE..PAYLOAD` |
| 8+N | 1 | `END` = `0x55` |

Total = `9 + N` bytes. CRC16-IBM sobre `TYPE..PAYLOAD`. Tipos: `DATA`,
`HEARTBEAT`, `REQUEST`, `RESPONSE`, `TIME`, `ACK`. Requisições:
`CAPTURE_LAST`, `CAPTURE_LIST`, `CAPTURE_CLEAR`, `LOG_EXPORT`, `LOG_INFO`.

O receptor (`HefSerialRx`) faz **varredura por frame íntegro** (início +
comprimento + `END` + CRC16): um byte `0xAA` perdido, um frame truncado ou um
frame corrompido não derruba os frames seguintes — o receptor ressincroniza
sozinho e contabiliza o erro. Isso é coberto por teste de round-trip no host
(`tests/serial_roundtrip.cpp`, 33 verificações).

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

### 5.4 Parâmetros de RF do link LoRa (Node 1 ↔ Node 2)

| constante | valor | nota |
|---|---|---|
| `LORA_FREQ` | 915 MHz | dentro da faixa de `915-ANATEL` e `915-FCC` |
| `LORA_SF` | 8 | era 10 na v5.0.0 (duty cycle inviável — ver §9.5) |
| `LORA_BW` | 125 kHz | |
| `LORA_TX_POWER` | 20 dBm | abaixo do EIRP máximo de referência do perfil |
| `LORA_TX_INTERVAL_MIN_MS` | 30 000 ms | era 1 000 ms na v5.0.0 |
| `LORA_TX_JITTER_PCT` | 10% | dessincroniza a frota |
| `HEF_BAND_PROFILE` | `915-ANATEL` | perfil regional de referência |

Fonte única de verdade: `lib/src/hefestos_pins.h`. O orçamento, os perfis e
o comando de console `budget` estão em
[§9.5](#95-orçamento-de-rf-e-conformidade-regulatória).

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
    peer_state.h         estado anti-replay persistido por par
    link_budget.h        tempo no ar, duty cycle e guard de orçamento de RF
    band_plan.h          perfis de banda regionais de referência
    tx_policy.h          política de TX adaptativa (evento/heartbeat) + beacon
    reset_tracker.h      causa de reinício e contadores de operação
    watchdog_policy.h    política do watchdog (puro, testável no host)
    watchdog.h           ligação do watchdog com o ESP-IDF
    totp_auth.h          TOTP RFC 6238
    rate_limiter.h       token buckets por IP
    debug.h              logging sem vazamento de segredos
src/
  Node1_Transmissor_Alvo/
  Node2_Base_Hefestos/
  Node3_Caixa_Preta_ESP32C3/
tests/
  framework.h           micro-framework de teste no host
  serial_roundtrip.cpp  teste de round-trip do protocolo serial (host)
  anti_replay_persistence.cpp  estado anti-replay persistido (host)
  link_budget.cpp       tempo no ar, duty cycle e guard de RF (host)
  tx_policy.cpp         política de TX adaptativa e beacon FM (host)
  reset_tracker.cpp     causa de reinício e contadores (host)
  watchdog_policy.cpp   política do watchdog (host)
  stub/HardwareSerial.h stub Arduino mínimo para compilar no host
tools/
  airtime.py            CLI de cálculo de RF (airtime/duty/energia) + --selftest
build.sh                 build dos 3 nós
test_functional.sh       invariantes + round-trip + anti-replay + RF + TX + WDT + build
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

**Node 1:** `help`, `status`, `policy`, `budget`, `id`, `psk <hex>`, `psk show`,
`fm on|off|rearm`, `fm freq <kHz>`, `fm power <0-255>`.

**Node 2:** `help`, `status`, `budget`, `id`, `psk`, `user`, `pass`, `totp`,
`wifi`, `settime`, `time`, `enroll <node> <keyid>`, `peers`,
`sweep on|off|now`, `radio <FM|AM|SW> <kHz>`, `resets`, `reboot`, `factory`.

> `budget` (Node 1 e Node 2) imprime o perfil regional, a faixa, o tempo no
> ar, o intervalo efetivo e o duty cycle consumido na janela de 1 h — ver
> [§9.5](#95-orçamento-de-rf-e-conformidade-regulatória).
>
> `policy` (Node 1) imprime a política de TX adaptativa e o estado do
> beacon FM — ver [§9.6](#96-política-de-tx-adaptativa-node-1).
>
> `resets` (Node 2 e Node 3) imprime a causa do boot e os contadores de
> reinício — ver [§9.7](#97-watchdog-brownout-e-causa-de-reinício-node-2--node-3--v510).

**Node 3:** `help`, `status`, `info`, `caps`, `clear`, `export`,
`time <unix>`, `format`, `resets`, `reboot`.

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
| GET | `/api/health` | heap, relógio, contadores, causa do reinício e estado do watchdog |
| GET | `/api/captures` | capturas do Node 3 (cache) |
| GET | `/api/logs` | estado do log forense |

### 9.3 Varredura de espectro

Plano padrão: FM 87,5–108 MHz (passo 250 kHz), AM 520–1710 kHz (20 kHz),
SW 2,3–30 MHz (100 kHz). A varredura é incremental: um ponto por `tick()`,
com dwell configurável (90 ms + 60 ms de settle por ponto) e restaura a
frequência do operador ao terminar. `auto=1` repete continuamente.
Com o plano padrão, um ciclo completo leva ~65 s (83 pontos FM + 60 AM +
277 SW).

### 9.4 Detecção de interferência

Estados: `NORMAL`, `DEGRADED` (SNR mediana abaixo do limite),
`NOISE_RISE` (piso de ruído do Si4735 subiu mais de 10 dB por 30 s) e
`LINK_LOSS` (nenhum frame LoRa há 15 s). As métricas vêm do RF real —
não de contadores que nunca eram atualizados.

### 9.5 Orçamento de RF e conformidade regulatória

#### 9.5.1 O que estava errado

A v5.0.0 operava o link LoRa com **SF10 a 1 frame/s**, sem nenhuma
verificação de orçamento de espectro. O ciclo completo (telemetria + ACK)
ocupava **2256,9 ms de tempo no ar a cada 1000 ms** — um **duty cycle de
225,7%**, fisicamente impossível (o enlace não pode ocupar mais de 100% do
tempo). O resultado prático era colisão permanente, fila no driver LoRa e
**6,5 Ah/dia só de transmissão** — mais que a bateria de 6,6 Ah do nó.

> Esses são os números do firmware v5.0.0 **como ele era** (ACK de 35 B,
> payload de 4 B). A tabela de [§9.5.2](#952-configuração-adotada) mantém o
> ACK atual nos dois lados, para isolar o efeito de SF e intervalo.

> **Correção de uma estimativa do próprio plano de escala.** O plano
>(original) calculava 4564 ms de tempo no ar para SF10/54 B e deduzia
> 757% de duty cycle. Esse número estava **errado**: a tabela oficial de
> airtime do RP002 (LoRaWAN Regional Parameters) dá **1312,8 ms** para
> SF10/54 B. A fórmula correta foi validada contra as 9 referências da
> tabela oficial (SF7/10/12 × 12/51/115 B, erro < 0,001 ms) e contra a lei
> de escalonamento exata `2^ΔSF`. A conclusão do plano (inviável) permanece,
> mas com o número correto: **225,7%**, e 6,5 Ah/dia — não 13,2 Ah/dia.
>
> A ferramenta `tools/airtime.py --selftest` é a fonte da verdade e está
> wired na suíte de testes, para que a fórmula não se degrade.

#### 9.5.2 Configuração adotada

| parâmetro | v5.0.0 | v5.1.0 |
|---|---|---|
| Spreading factor | SF10 | **SF8** |
| Intervalo de TX | 1 s (via `GPS_POLL_INTERVAL_MS`, constante enganosa) | **30 s** (`LORA_TX_INTERVAL_MIN_MS`) |
| Política de TX | **periódica** (1 frame/30 s) | **adaptativa**: por movimento ou heartbeat (§9.6) |
| Jitter | nenhum | **±10%** (`LORA_TX_JITTER_PCT`) |
| Tamanho do ACK | 35 B (payload redundante de 4 B) | **33 B** (payload de 2 B: flags + RSSI) |
| Tempo no ar (telemetria 54 B) | 1312,8 ms | **328,2 ms** |
| Tempo no ar (ACK 33 B) | 903,2 ms | **225,8 ms** |
| Ciclo completo | 2215,9 ms | **554,0 ms** |
| **Duty cycle** | **221,6%** (inviável) | **1,85%** |
| TX por dia (120 mA @ 20 dBm) | 6,38 Ah | **0,053 Ah** |

SF8 também entrega **≈3× mais alcance** que SF10 para a mesma potência
(ganho de ~10,5 dB no enlace) — o que, no contexto de uma frota, vale mais
do que a taxa bruta.

> **Como ler a tabela.** A coluna "v5.0.0" mantém o **ACK atual de 33 B**
> para isolar o efeito da mudança de SF e de intervalo. O firmware v5.0.0
> usava um ACK de **35 B**: com ele, o duty cycle era **225,7%** e o consumo
> **6,50 Ah/dia**. Os dois valores são inviáveis — a magnitude é que muda.

> O firmware arredonda o airtime **para cima** (ms inteiros) ao aplicar o
> orçamento: 329 + 226 = 555 ms, o que dá 1,850% — 0,003 p.p. acima do
> valor exato de 1,847% da tabela. É uma folga deliberada a favor do
> operador.

> Com a TX adaptativa (§9.6), o duty cycle e o consumo acima passam a ser
> o **pior caso**: um alvo parado transmite só o heartbeat (1 frame/60 s),
> ou seja ~0,9% de duty cycle e 0,026 Ah/dia. O alvo em movimento
> permanente fica no regime de 30 s.

#### 9.5.3 Perfis regionais de referência

`lib/src/band_plan.h` define perfis por região. O perfil ativo é o de
compilação (`HEF_BAND_PROFILE`, padrão `915-ANATEL`).

| perfil | faixa | SF/BW/CR | EIRP máx | duty cycle |
|---|---|---|---|---|
| `915-ANATEL` | 915–928 MHz | SF8 / 125 kHz / 4/5 | 30 dBm | 10% (orçamento próprio) |
| `915-FCC` | 902–928 MHz | SF8 / 125 kHz / 4/5 | 30 dBm | 10% (orçamento próprio) |
| `868-ETSI` | 868–870 MHz | SF8 / 125 kHz / 4/5 | 14 dBm | 1% (normativo) |

> **Sub-bandas ETSI:** o duty cycle de 1% vale para a faixa 868,7–869,2 MHz;
> as sub-bandas 868,0–868,6 MHz e 869,4–869,65 MHz têm limite de **0,1%**
> (com o firmware atual, isso exigiria um intervalo de ~9,4 min). A sub-banda
> exata precisa ser confirmada antes de operar.

> ⚠️ **Estes valores são referência de engenharia, NÃO parecer jurídico.**
> Os limites regulatórios variam por país, por sub-banda, por modalidade de
> acesso (FHSS, DSSS, LPD/CHIP) e por classe de equipamento. Os limites de
> duty cycle em `915-ANATEL` e `915-FCC` são **auto-impostos e
> deliberadamente conservadores** — essas normas não fixam um duty cycle
> geral para a faixa ISM. O **operador é o único responsável** por confirmar
> o perfil, a sub-faixa, o EIRP e os limites vigentes (ANATEL, FCC, ETSI)
> antes de operar. Emitir em frequências reguladas sem autorização é ilegal
> na maioria das jurisdições.

#### 9.5.4 O firmware impede a violação

O orçamento não é apenas documentação: o firmware **recusa** a
transmissão quando ela violaria o limite do perfil.

- `HefDutyGuard` (`lib/src/link_budget.h`) mantém uma **janela deslizante
  de 1 hora**, discretizada em baldes de 1 minuto, com o airtime acumulado.
- **Node 1** verifica `dutyGuard.allows()` **antes** de gastar energia na
  telemetria; se violaria, a transmissão é suspensa e o contador
  `txDenied` é incrementado.
- **Node 2** faz o mesmo no `sendAck()` — o ACK da base **é uma
  transmissão** e consome espectro. Contador: `acksDenied`.
- O **intervalo efetivo** entre ciclos é o maior entre: o configurado, o
  mínimo do perfil e o intervalo que o duty cycle exige. Com o perfil
  `868-ETSI` (1%), o intervalo é automaticamente alongado para ~55,5 s
  (o firmware arredonda o airtime para cima: 555 ms × 100 / 1%).
- O **jitter de ±10%** dessincroniza a frota: várias unidades acordando
  juntas colidiriam no mesmo instante. O jitter é sorteado dentro da
  política de TX (§9.6), com a fonte de aleatoriedade injetada — assim a
  lógica é testável no host com RNG determinístico.

Falha fechada: em caso de dúvida (parâmetros inválidos, limite zero), o
firmware **não transmite**.

#### 9.5.5 Verificação

```console
# Node 1 — console serial
budget
perfil: 915-ANATEL (Brasil (ANATEL))
faixa: 915.000-928.000 MHz | SF8 BW125 CR4/5 | EIRP<=30 dBm
airtime: track=329 ms ack=226 ms ciclo=555 ms
intervalo: 30000 ms | duty: 1.850% (limite 10.0%)
energia TX: 0.0185 mAh/ciclo | 53.280 mAh/dia (120 mA)
duty na janela de 1h: 0.009% | transmissoes negadas: 0

# Node 2 — console serial
budget
perfil: 915-ANATEL (Brasil (ANATEL))
faixa: 915.000-928.000 MHz | SF8 BW125 | EIRP<=30 dBm | 915 kHz OK
airtime: track=329 ms ack=226 ms
energia TX (ACK): 0.0075 mAh/ACK (120 mA)
duty 1h: 0.006% (limite 10.0%) | ACKs negados: 0
```

> O `duty` de regime (1,850%) é o do ciclo **periódico**; o `duty na janela
> de 1 h` é o consumo **acumulado** desde o boot.

```bash
# Ferramenta de cálculo (host) — a mesma fórmula do firmware
python3 tools/airtime.py --selftest              # valida contra o RP002
python3 tools/airtime.py --profile 915-ANATEL --sf 8 --interval 30000
python3 tools/airtime.py --profile 868-ETSI --sf 8 --interval 30000
python3 tools/airtime.py --sweep                 # tabela SF × intervalo
```

A API do Node 2 expõe o orçamento em `/api/status`:

```json
"rf_budget": {
  "profile": "915-ANATEL", "region": "Brasil (ANATEL)",
  "freq_min_khz": 915000, "freq_max_khz": 928000, "eirp_max_dbm": 30,
  "sf": 8, "bw_khz": 125, "airtime_ack_ms": 226,
  "duty_limit_pct": 10.0, "duty_used_pct": 0.006, "freq_ok": true
}
```

### 9.6 Política de TX adaptativa (Node 1)

Até a v5.1.0 o Node 1 transmitia **periodicamente**: um frame a cada 30 s,
importando ou não o alvo ter se movido. Numa frota, isso é desperdício de
espectro e de energia — e, pior, **não distingue um alvo parado de um
alvo que saiu de campo**.

Agora a transmissão é **por evento**:

```
transmite se:   posição alterou > LORA_MIN_MOVE_M (10 m)
             OU passou LORA_HEARTBEAT_TX_MS (60 s) desde a última TX
             E o piso de intervalo (30 s, derivado do duty cycle) passou
```

O **heartbeat** é indispensável: é ele que mantém a base ciente de que a
unidade está viva. Sem ele, um alvo parado seria indistinguível de um alvo
que ficou sem bateria ou saiu da área de cobertura.

| evento | contador | console |
|---|---|---|
| posição alterou além do limiar | `txEvents` | `Evento: alvo se moveu 44.5 m` |
| heartbeat (alvo parado) | `txHeartbeats` | — |
| suprimido pelo duty cycle | `txDenied` | `TX suspensa: duty cycle ...` |
| **evento sem frame no ar** | `txSuppressed` | `Evento sem frame no ar: posicao nao reportada` |

```console
# Node 1
policy
TX: movimento > 10 m OU heartbeat 60 s | piso 30 s +/- 10%
   ultimo: 120000 ms | proximo permitido: 149375 ms | distancia: 44.5 m
beacon FM: ligado | duty 10.0% (3 s on / 27 s off) | min bateria 20%
```

#### 9.6.1 Detalhes que importam

- **A referência de posição é a do último frame REPORTADO**, não a da
  última posição observada. Consequência direta: **se a transmissão for
  negada (duty cycle, erro), o movimento não é perdido** — ele continua
  pendente e é reportado na próxima oportunidade. O contador
  `txSuppressed` torna visível quantos eventos ficaram sem frame no ar.
- **O piso de intervalo é verificado antes de consumir o evento.** Um
  movimento ocorrido durante o piso não é descartado: a posição corrente
  continua pendente e o evento é detectado na primeira avaliação após o
  piso.
- **A transmissão negada reprograma o piso** (`onTxFailed()`). Sem isso, o
  loop principal — que chama `evaluate()` milhares de vezes por segundo —
  re-tentaria a cada iteração, cada tentativa incrementando `txDenied` e
  escrevendo no log. Um flood assim, sozinho, esgota a flash e o buffer
  da serial. O piso vale **também antes do primeiro contato**.
- **Sem fix GNSS, só o heartbeat dispara.** Não é possível estimar
  movimento sem posição; e é justamente nesses casos que a base mais
  precisa saber que o nó está online.
- **A primeira posição válida é reportada como evento.** Se o nó
  transmissions sem fix (num túnel, por exemplo), a referência fica
  inválida e a próxima posição válida é tratada como "primeira posição":
  a base ainda não conhece **nenhuma** posição daquele nó, e precisa
  recebê-la.

#### 9.6.2 ACK curto (2 bytes)

O ACK da base passou de **4 bytes de payload para 2**:

| byte | conteúdo |
|---|---|
| 0 | flags: `OK`, `DUPLICATE`, `GPS_VALID` |
| 1 | RSSI do frame recebido, quantizado (0..255 ⇒ −130..−3 dBm) |

Os 4 bytes anteriores eram **redundantes**: repetiam o contador, que já
está no cabeçalho do frame — e o cabeçalho é autenticado como AAD pelo
GCM. O payload de 2 bytes carrega informação **nova**: o emissor passa a
saber a qualidade do link vista pela base (antes era cego).

O frame no ar cai de 35 B para 33 B e o tempo no ar do ACK de 236,0 ms
para 225,8 ms (SF8).

#### 9.6.3 Retentativa: 1 por evento

A v5.0.0 fazia até **3 transmissões** por evento (1 original + 2 retries).
Agora são no máximo **2** (1 original + 1 retry).

O retry reutiliza o **mesmo `(epoch, counter)`**: a retransmissão é
segura porque a base reconhece a duplicidade pelo contador, reenvia o ACK
sem reprocessar o track, e o anti-replay permanece estrito.

O contador é alocado **uma vez por evento** e repassado à retentativa.
Isso eliminou um bug latente da v5.0.0: o `TxSequence` tinha um
`setCounter()` que permitia "desfazer" a alocação, e a retransmissão o
usava para reescrever o contador. Se a reescrita ocorresse **depois** de
um frame já ter saído, o próximo evento reutilizaria um contador que a
base **já tinha aceito** — e a base rejeitaria um frame legítimo como
`REPLAY`, matando o enlace. O setter foi **removido**: a sequência de
contadores é estritamente monotônica, e uma alocação desperdiçada apenas
abre uma lacuna, que o receptor trata normalmente.

> O teste `tests/anti_replay_persistence.cpp` demonstra o ciclo completo:
> a base aceita o contador 1, o emissor o reusa, e a base **rejeita** o
> frame (`REPLAY`) — provando que qualquer reuso de contador é fatal.

#### 9.6.4 Beacon FM: duty cycle próprio e corte por bateria

O beacon FM (Si4713) é um transmissor **independente** do link LoRa: tem
o próprio orçamento de energia e de espectro.

| parâmetro | valor | efeito |
|---|---|---|
| `FM_BEACON_ON_MS` | 3 000 ms | fase ligada |
| `FM_BEACON_OFF_MS` | 27 000 ms | fase desligada → **10% de duty** |
| `FM_BEACON_MIN_BATTERY_PCT` | 20% | abaixo disso, **desliga** |

O corte por bateria é **automático e travado**: o beacon não se religa
sozinho (nem com a voltando a 90%) — é preciso `fm rearm` no console,
depois de uma recarga. Preservar o link LoRa (que é o que mantém a base
ciente da unidade) tem prioridade sobre um beacon audível.

> ⚠️ **Validação de bancada pendente.** O corte de radiação usa a
> propriedade `PROP_TX_ENABLE` (0x3E06) do Si4713, que não pôde ser
> exercitada neste ambiente (nenhum Si4713 conectado). **Validar em
> bancada** que o beacon realmente cessa de radiar na fase OFF e no corte
> por bateria antes de operar em campo.

---

### 9.7 Watchdog, brownout e causa de reinício (Node 2 / Node 3) — v5.1.0

#### 9.7.1 O que estava errado

Na v5.0.0 o dispositivo **não registrava por que reiniciou**. O boot
imprimia um banner e seguia. Um aparelho que reiniciou 500 vezes por
*brownout* (queda de alimentação) e um que reiniciou 500 vezes por
*travamento de software* eram **indistinguíveis** no log — e são falhas de
naturezas completamente diferentes: uma é problema de energia, a outra é
bug de software, e tratam-se de formas diferentes.

Pior: **não havia watchdog sobre o loop principal**. O TWDT do IDF só
vigiava a task idle. Um travamento em `loop()` — onde vive praticamente
toda a lógica — não era detectado: o aparelho ficava "vivo" mas inútil,
com o HTTP sem resposta e o log forense parado de crescer, **sem
qualquer indicação**.

#### 9.7.2 Watchdog de tarefa

| item | valor |
|---|---|
| timeout pedido | `HEF_WDT_TIMEOUT_S` = **30 s** |
| alimentações por janela | `HEF_WDT_FEED_DIVISOR` = 3 (intervalo efetivo 5 s) |
| detector de brownout | ativo no build (`CONFIG_ESP32_BROWNOUT_DET=y` / `CONFIG_ESP32C3_BROWNOUT_DET=y`) |

O core Arduino-ESP32 2.0.17 alimenta o TWDT **antes de cada `loop()`**
(quando `loopTaskWDTEnabled` está ligado). Como `enableLoopWDT()`
inscreve a task do loop, **um travamento dentro de `loop()` não é
alimentado e o TWDT dispara o panic handler**: o chip reinicia com causa
`ESP_RST_TASK_WDT` em menos de 30 s.

O estado do watchdog é **reportado com honestidade**:

- `watchdog_active` — o watchdog está realmente inscrito?
- `watchdog_timeout_s` — o timeout **efetivo**. Se o TWDT já existia
  (inicializado por outro componente) e o IDF 4.4 não permite ler o
  timeout em vigor, o valor reportado é **0 (desconhecido)** — nunca uma
  mentira. O console imprime `timeout pre-existente` nesse caso.
- Se a inicialização **falhar**, o console imprime
  `watchdog: INATIVO (falha na inicializacao)`. Um watchdog que não
  inicializou é pior do que nenhum: o operador poderia acreditar que
  existe proteção que não existe.

#### 9.7.3 Operações longas: progresso sem mascarar travamento

Operações que podem levar **minutos** (releitura da cadeia de hash do
log forense, exportação JSONL, gravação do vault) alimentam o watchdog
durante a execução.

O ponto criticalmente importante: **o progresso só é reportado em pontos
onde a operação realmente avançou**. Um SD que trava no meio **deixa de
reportar progresso**, e o watchdog expira normalmente — o travamento vira
um reinício com causa visível, em vez de ficar mascarado. O guarda de
progresso (`HefProgressGuard`) é uma **consulta**, não uma ação: ele só
responde "o WDT precisa de alimentação?"; quem alimenta é o chamador, e
só depois de um avanço real.

No Node 3 isso é implementado por um callback de progresso no
`FieldLog`, acionado a cada registro processado.

#### 9.7.4 Contadores de reinício

| contador | significado |
|---|---|
| `boots` | total de inicializações |
| `brownouts` | reinícios por queda de alimentação |
| `wdt_resets` | reinícios por watchdog (tarefa, interrupção ou genérico) |
| `sw_resets` | reinícios por software (`ESP.restart()`, deep sleep) |
| `panics` | reinícios por panic/exceção |

**Guarda de desgaste da NVS.** Cada gravação na NVS consome vida útil da
partição. Numa operação normal isso é irrelevante, mas num **laço de
brownout** — a alimentação oscila e o aparelho reinicia 50 vezes por
hora — a NVS sofreria 438 mil escritas por ano. Por isso:

- a gravação **imediata** só acontece quando a **causa mudou** (um
  brownout depois de um boot normal é evento novo e relevante) ou a cada
  `HEF_RESET_PERSIST_EVERY_BOOTS` (10) boots;
- o resto fica acumulado em RAM e é gravado no flush periódico
  (`HEF_RESET_FLUSH_MS` = 5 min);
- a **causa do último reinício é sempre exata** — é ela que o operador
  precisa, e ela nunca fica defasada.

Os contadores vivem num namespace NVS próprio (`hefrst`), **não** no
vault cifrado: contadores de operação não são segredo, e o vault é
reescrito **inteiro** a cada gravação — caro demais para um contador.

#### 9.7.5 Reinício controlado

Um `ESP.restart()` sem registro é um reinício **cego**. Todo reinício
agora passa por `hefRestart()`, que grava a **intenção** (pedido pelo
operador? falha automática?) antes de sair. O console mostra o motivo:

```console
# Node 2
resets
causa do boot: brownout (9)
boots=42 brownouts=7 wdt=1 sw=31 panic=0
causa persistida: brownout | watchdog: ativo (30 s)
motivo do reinicio anterior: desconhecida
```

A **intenção é lida e consumida** no boot seguinte: ela só vale para
aquele boot (a `sequence` tem de bater com o número do boot) e é
removida depois de lida. Sem essa checagem, um `reboot` do operador
deixaria uma intenção "pendente" que continuaria aparecendo em **todos**
os boots seguintes — dizendo "reinício solicitado pelo operador" em
reinícios que foram, na verdade, travamentos. Informação errada é pior do
que a ausência dela.

A causa do boot e o estado do watchdog estão também em
`GET /api/health` (Node 2) e no JSON de log do Node 3 (visível na base
pelo painel):

```json
{
  "reset_reason": "brownout",
  "reset_reason_code": 9,
  "reset_fault": false,
  "reset_brownout": true,
  "boots": 42, "brownouts": 7, "wdt_resets": 1, "sw_resets": 31, "panics": 0,
  "reset_intent": "solicitado pelo operador",
  "reset_intent_kind": 1,
  "watchdog_active": true,
  "watchdog_timeout_s": 30
}
```

> ⚠️ **Aceite de bancada pendente.** O critério do item 1.4 é *"travamento
> real do loop principal provoca reinício em < 30 s com causa `WDT`
> visível"*. Não há hardware neste ambiente, então o reinício por WDT
> **não foi exercitado em campo**. Validar em bancada antes de operar:
> travar o `loop()` de propósito (ex.: um `while(true)` sem `delay`) e
> confirmar o reinício com causa `wdt-tarefa` no console e em
> `/api/health`.

#### 9.7.6 Checklist de validação em bancada

| # | Teste | Resultado esperado |
|---|---|---|
| 1 | Travar o `loop()` (ex.: `while(true);` sem `delay`) | reinício em **< 30 s** |
| 2 | Console do boot seguinte | `reinicio: wdt-tarefa` |
| 3 | `GET /api/health` | `reset_reason: "wdt-tarefa"`, `wdt_resets` incrementado |
| 4 | Cortar a alimentação durante o boot | boot seguinte com `reinicio: brownout`, contador `brownouts` incrementado |
| 5 | `reboot` no console | `Reiniciando (intencao=1, causa=software)...` e boot seguinte com `sw_resets` incrementado |
| 6 | `heap critico` forçado | reinício com `intencao=2` (falha automática) |
| 7 | Node 3 com log grande: `export` | **sem reinício** (progresso reportado) |
| 8 | Node 3 com SD travado: `export` | **reinício por WDT** (travamento não mascarado) |

Os testes 7 e 8 são o par que valida a propriedade central do item 1.4:
**o watchdog distingue "operação lenta legítima" de "operação travada"**.

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
./test_functional.sh            # invariantes + round-trip + RF + politica + WDT + build
./test_functional.sh --no-build # sem build (não precisa do toolchain ESP32)
```

Cobertura (11 grupos):

1. pinagem duplicada e pinos proibidos no ESP32-C3;
2. layout do frame LoRa (offsets do cabeçalho, `HEF_MAX_FRAME`);
3. **round-trip real do protocolo serial** (`tests/serial_roundtrip.cpp`,
   executado no host com `g++`): payload com `0xAA`/`0x55`, frames
   concatenados, frame corrompido, frame truncado, feed byte a byte e
   payload máximo;
4. ausência de Telnet/EEPROM/include relativo;
5. anti-replay estrito e TOTP verificado no login;
6. dashboard sem injeção de HTML e ausência de chaves hardcoded;
7. **estado anti-replay persistido** (`tests/anti_replay_persistence.cpp`,
   85 verificações no host): serialização do estado por par, reidratação,
   rejeição de epoch anterior, rejeição de contador repetido, salto acima do
   limite, **monotonicidade do contador do emissor** (com o ciclo completo
   em que a base rejeita um contador reusado), e o cenário crítico de
   replay de frame capturado após reinício do receptor — com um bloco que
   demonstra explicitamente que **sem** a reidratação o mesmo frame seria
   aceito (a vulnerabilidade da v5.0.0);
8. **orçamento de RF** (`tests/link_budget.cpp`, 57 verificações no host):
   tempo no ar contra as 9 referências da tabela oficial do RP002, lei de
   escalonamento `2^ΔSF`, valores do projeto, parâmetros inválidos,
   intervalo mínimo por perfil, **coerência entre o tamanho real do frame
   e o cálculo de airtime**, e o **guard de duty cycle** (que precisa
   *recusar* a transmissão que violaria o limite). O grupo também executa
   `tools/airtime.py --selftest` (mesma fórmula, lado Python) e verifica
   estaticamente que os parâmetros do firmware são viáveis e que o guard
   está aplicado no Node 1 **e** no Node 2;
9. **política de TX adaptativa** (`tests/tx_policy.cpp`, 77 verificações no
   host): distância por Haversine, disparo por movimento, supressão abaixo do
   limiar, heartbeat com o alvo parado, comportamento sem fix GNSS, piso de
   intervalo sob movimento perpétuo, **evento não perdido durante o piso**,
   **movimento pendente preservado quando a TX é negada** (com o piso
   reprogramado para evitar flood), **primeira posição válida reportada**,
   **piso válido antes do primeiro contato**, jitter do piso (com RNG
   determinístico), e a política do beacon FM (duty cycle próprio e corte
   por bateria). O grupo verifica também, por análise estática, que o Node 1
   usa a política adaptativa, que o retry é limitado a 1 por evento, que o
   ACK curto está coerente entre os dois nós, que **o contador do emissor
   não pode ser reescrito** e que **o movimento pendente sobrevive a uma
   TX negada**;
10. **causa de reinício e watchdog** (`tests/reset_tracker.cpp`,
    108 verificações + `tests/watchdog_policy.cpp`, 188 verificações no
    host): classificação de cada causa do ESP-IDF, contadores por
    classe, serialização/deserialização do estado (round-trip),
    saneamento de blob corrompido (fail-safe), guarda de desgaste da
    NVS, resolução do estado do watchdog a partir do resultado da init
    (OK / já-inicializado / falha real), **honestidade do timeout
    reportado** (nunca mente), cálculo do intervalo de alimentação das
    operações longas com o invariante de que o intervalo cabe na janela
    do WDT, e a propriedade de que **o guarda é uma consulta** (um
    código travado não o chama, e portanto o WDT expira — o travamento
    não é mascarado). O grupo verifica também, por análise estática,
    que os dois nós iniciam o watchdog e registram a causa do boot,
    que a causa é **visível na API**, que **todo reinício passa por
    `hefRestart()`** (nenhum `ESP.restart()` cru), que as operações
    longas reportam progresso, que os contadores de reinício têm
    guarda de desgaste e que a **intenção do reinício é lida e
    consumida** (uma intenção não consumida reapareceria em todos os
    boots seguintes, dizendo "reinício solicitado pelo operador" em
    reinícios que foram travamentos);
11. build dos três nós.

O round-trip do protocolo serial existe porque um erro de offset de 1 byte
no parser de frames já passou pelo build e pelos testes estáticos: o código
compilava e o link Node2↔Node3 simplesmente nunca funcionava em campo. O
teste de anti-replay existe pelo mesmo motivo: a falha era **silenciosa** e
só apareceu em análise do modelo de ameaça, não em nenhum teste. O teste de
orçamento de RF existe pelo mesmo motivo: um duty cycle de 221% é
**matematicamente impossível** e nenhuma compilação ou revisão de código o
apontava. O de TX adaptativa existe porque a política tem **arestas não
óbvias** (movimento perdido quando a TX é negada, flood de log, heartbeat
que nunca dispara, contador de frame reusado) que só aparecem em
simulação.

O teste do watchdog existe porque **códigos de erro errados passam
invisíveis**. A v5.1.0 usava `-1` e `-12` para `ESP_ERR_INVALID_STATE` e
`ESP_ERR_NO_MEM`, mas os códigos reais do `esp_err.h` são `0x103` (259) e
`0x101` (257). Com os valores errados, uma falha de memória era
classificada como "TWDT já inicializado" e o resolvedor devolvia
`active = true`: o console e a API passavam a reportar **"watchdog: ativo"**
num dispositivo **sem watchdog** — a proteção aparecia na telemetria sem
existir. É a mesma classe de defeito do duty cycle de 221%: nada no build
nem na revisão de código apontaria.

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
| Node reinicia em laço | brownout (energia) | `resets` → ver `brownouts`; revisar fonte |
| Node reinicia em laço | travamento de software | `resets` → ver `wdt`/`panics`; investigar |
| `watchdog: INATIVO` no boot | falha na inicialização do TWDT | investigar; o dispositivo está sem proteção |
| `watchdog_timeout_s: 0` | TWDT pré-existente, timeout desconhecido | estado real, não uma falha (IDF 4.4 não expõe a leitura) |
| Frame rejeitado como replay | emissor reiniciou sem novo epoch | reiniciar o Node 1 (epoch novo) |

---

## 13. Rotação de chaves e reset

- **Rotação de PSK:** grave o novo PSK em todos os nós (`psk ...`), reinicie.
  O Node 2 re-deriva a chave de cada par no primeiro frame válido.
- **Reset de fábrica (Node 2):** `factory` apaga PSK, enrollments, credenciais
  e TOTP. O chip continua o mesmo (a chave do vault é derivada do MAC).
- **Node 3:** `format` apaga o log e recria o cabeçalho. Isso **destrói** a
  cadeia anterior; exporte antes.

### 13.1 Credenciais de versões antigas

A v4.x commitou no repositório uma senha de Wi-Fi e credenciais fixas. O
histórico do Git foi reescrito (`git filter-repo`) para remover:

- as credenciais fixas da v4.x (senha de Wi-Fi e segredos de TOTP);
- os artefatos de build versionados (`.bin`, `.elf`, `.map`, `sdkconfig`);
- os documentos `IMPLEMENTATION_GUIDE_v2.md` e `OPERATION_MANUAL_v2.md`,
  obsoletos e contraditórios com o código real.

Consequências práticas:

- **Qualquer credencial que tenha sido usada na v4.x deve ser considerada
  comprometida.** Troque a senha do Wi-Fi, a senha HTTP e cadastre um novo
  TOTP antes de colocar o equipamento em campo.
- Clientes existentes precisam recomeçar (`git clone` novo ou
  `git fetch && git reset --hard origin/main`); os hashes antigos não existem
  mais localmente.
- Se o repositório remoto já tinha publicado essas credenciais, o purge só
  tem efeito após um *force-push* do histórico reescrito — e mesmo assim o
  valor deve ser considerado comprometido.

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
- **Janela residual de replay intra-epoch:** o high-water do contador é
  persistido a cada 60 s. Um reinício dentro dessa janela permite que um frame
  capturado do *mesmo* epoch, com contador até 60 s atrás, seja aceito. Epoch
  anterior é sempre rejeitado. Reduzir `HEF_PEER_STATE_FLUSH_MS` estreita a
  janela ao custo de desgaste de flash (ver §3.5.1).
- **Epoch de 16 bits:** o emissor sorteia um epoch novo por boot. Após ~65 536
  boots o epoch pode dar a volta (aritmética de número de série). Migrar para
  epoch de 32 bits na v6.
- **Duty cycle do link:** viabilizado na v5.1.0 (SF8 a 1/30 s → 1,85%).
  A TX é **adaptativa** (§9.6): um alvo parado transmite só o heartbeat
  (1 frame/60 s). O número de frames observados em campo depende do
  movimento real da unidade e não pode ser previsto por firmware.
- **Beacon FM: validação de bancada pendente.** O corte de radiação usa a
  propriedade `PROP_TX_ENABLE` (0x3E06) do Si4713, que não pôde ser
  exercitada neste ambiente (nenhum Si4713 conectado). Confirmar em
  bancada que o beacon cessa de radiar na fase OFF e no corte por bateria
  (§9.6.4).
- **Watchdog: aceite de bancada pendente.** O critério do item 1.4 é
  *"travamento real do loop principal provoca reinício em < 30 s com
  causa `WDT` visível"*. Não há hardware neste ambiente, então o
  reinício por WDT não foi exercitado. Confirmar em bancada (§9.7.6).
- **Timeout do watchdog pode ser desconhecido.** Se outro componente já
  tiver inicializado o TWDT, o IDF 4.4 não expõe a leitura do timeout em
  vigor: o valor reportado é `0` (desconhecido), não uma estimativa. O
  IDF 5.x (core 3.x, previsto para a Fase 4) expõe a leitura e resolverá
  essa limitação.
- **`setup()` não é protegido pelo watchdog.** O core Arduino alimenta o
  TWDT apenas **antes de cada `loop()`**; durante o `setup()` a task fica
  sem alimentação. As operações potencialmente longas do setup (espera
  pelo Wi-Fi STA, até 15 s; releitura da cadeia do SD) alimentam o WDT
  explicitamente. Uma falha que travasse o `setup()` **sem ultrapassar
  os pontos de avanço** só seria detectada por causa do brownout ou por
  um watchdog externo.
- **Contadores de reinício podem ficar alguns boots atrás.** A guarda de
  desgaste da NVS (§9.7.4) adia a gravação para pouvar a partição. A
  **causa** do último reinício é sempre exata; os **totais** podem
  defasar em até `HEF_RESET_PERSIST_EVERY_BOOTS` (10) boots.
- **Consumo real ainda não medido.** O item 1.3 do plano tem aceite
  "≤ 0,5 Ah/dia medido em bancada". As estimativas de firmware cobrem
  **apenas o TX LoRa** (0,053 Ah/dia no pior caso). Os consumos
  dominantes — **GNSS** (tracking contínuo a 1 Hz) e **RX do SX1276** em
  espera de ACK — são ordens de grandeza maiores e dependem do item 1.7
  (deep sleep). Sem o item 1.7, a autonomia de 14 dias **não é
  atingível**, mesmo com a TX adaptativa.
- **Perfis de banda são referência de engenharia, não parecer jurídico.**
  Os limites de duty cycle de `915-ANATEL`/`915-FCC` são auto-impostos e
  conservadores; o operador deve confirmar o perfil aplicável e os limites
  vigentes na sua jurisdição antes de operar (ver §9.5.3).

---

## 15. Licença

Ver `LICENSE`. Uso sujeito às leis de telecomunicações aplicáveis.
