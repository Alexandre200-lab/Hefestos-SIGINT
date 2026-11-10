// hefestos_pins.h - Definicoes centralizadas de pinagem e constantes (v5.0.0)
//
// Fonte unica de verdade para:
//   - Pinagem dos 3 nos
//   - Numeros de versao de firmware
//   - Constantes do protocolo de link LoRa
//   - Limites operacionais (sessoes, filas, buffers)
//
// QUALQUER alteracao de pin aqui DEVE ser refletida no README.md
// (secao 5 - Hardware e pinagem).
#ifndef HEFESTOS_PINS_H
#define HEFESTOS_PINS_H

// ============================================================
// FIRMWARE
// ============================================================
#define HEF_FW_VERSION_MAJOR 5
#define HEF_FW_VERSION_MINOR 1
#define HEF_FW_VERSION_PATCH 0
#define HEF_FW_VERSION_STR "5.1.0"

// ============================================================
// Node 1 - Transmissor / Alvo (ESP32-WROOM-32)
// ============================================================
#define N1_LORA_SS        5
#define N1_LORA_RST      14
#define N1_LORA_DIO0     26
#define N1_FM_RST        32
#define N1_FM_I2C_SDA    21
#define N1_FM_I2C_SCL    22
#define N1_GPS_RX        16
#define N1_GPS_TX        17
#define N1_RF_SWITCH     25
#define N1_BAT_ADC       36   // ADC1_CH0 - sensor de bateria (divisor resistivo)
#define N1_SERIAL_LOG    0   // console UART0 (USB-UART)
#define N1_SERIAL_GPS    2   // UART2 -> NEO-6M

// ============================================================
// Node 2 - Base / Posto de Sensores (ESP32-WROOM-32)
// ============================================================
#define N2_LORA_SS        5
#define N2_LORA_RST      14
#define N2_LORA_DIO0     26
#define N2_RX_RST        13
#define N2_I2C_SDA       21
#define N2_I2C_SCL       22
#define N2_UART_TX       17
#define N2_UART_RX       16
#define N2_SERIAL_LOG    0   // console UART0 (USB-UART) - RESERVADO p/ debug
#define N2_SERIAL_LINK   2   // UART2 -> Node3 (Caixa Preta)

// ============================================================
// Node 3 - Caixa Preta / Logger forense (ESP32-C3)
//
// Pins 4/5/6/10 = FSPI padrao do ESP32-C3 (SCK/MISO/MOSI/CS).
// UART0 (console) usa os pinos padrao 20/21, portanto o link com o Node2
// vai para GPIO0 (RX) e GPIO2 (TX). GPIO2 e' strapping (precisa estar em
// nivel alto no boot) e a linha TX ociosa da UART ja' fica em nivel alto;
// recomenda-se pull-up externo de 10k em GPIO2.
// Evitados: GPIO8/9 (strapping), GPIO12-17 (bus SPI0 do flash),
//           GPIO18/19 (USB-JTAG), GPIO20/21 (UART0).
// ============================================================
#define N3_SD_CS         10
#define N3_SD_MOSI        6
#define N3_SD_MISO        5
#define N3_SD_SCK         4
#define N3_UART_RX        0
#define N3_UART_TX        2
#define N3_LED_GREEN      7
#define N3_LED_RED        1
#define N3_BUZZER         3
#define N3_SERIAL_LOG    0   // console UART0 (USB / UART0 de download)
#define N3_SERIAL_LINK   1   // UART1 -> Node2

// ============================================================
// PROTOCOLO DE LINK (LoRa) - ver link_protocol.h
// ============================================================
#define HEF_LINK_MAGIC        0xA5
#define HEF_LINK_VERSION      5
#define HEF_HEADER_LEN        15
#define HEF_TAG_LEN           16
#define HEF_IV_LEN            12
#define HEF_KEY_LEN           32      // AES-256
#define HEF_MAX_PAYLOAD       200
#define HEF_MAX_FRAME         (HEF_HEADER_LEN + HEF_MAX_PAYLOAD + HEF_TAG_LEN)
#define HEF_COUNTER_WINDOW    1024    // bits do bitmap anti-replay
// Salto maximo aceito do contador dentro da MESMA epoch.
// O bitmap de 1024 bits serve para CONTAR pacotes perdidos (diagnostico),
// nao para rejeitar: uma queda de link longa produz um salto maior que a
// janela e ainda e' um frame legitimo. Acima deste limite o frame e'
// rejeitado (falha fechada) e o enlace so ressincroniza com um epoch novo
// (o emissor reiniciado).
#define HEF_COUNTER_MAX_GAP   65536UL

// ============================================================
// LORA
// ============================================================
// v5.1.0 - CORRECAO DE VIABILIDADE DE RF
//   A v5.0.0 usava SF10 com 1 frame/s: o ciclo completo (telemetria + ACK)
//   ocupa 2256,9 ms de tempo no ar a cada 1000 ms -> duty cycle de 225%.
//   Isso e' fisicamente impossivel (o enlace nao pode ocupar mais de 100%
//   do tempo): o resultado e' colisao permanente, fila no driver LoRa e
//   consumo de 6,5 Ah/dia so de TX.
//
//   Com SF8 e um intervalo de 30 s o ciclo cai para 564,2 ms:
//     duty cycle 1,88%  |  TX 0,054 Ah/dia  |  alcance 3x maior que SF10.
//
//   TEMPO NO AR (formula validada contra a tabela RP002, ver
//   tools/airtime.py --selftest):
//     SF10: telemetria 1312,8 ms + ACK 944,1 ms = 2256,9 ms
//     SF8 : telemetria  328,2 ms + ACK 236,0 ms =  564,2 ms
//
#define LORA_FREQ          915E6
#define LORA_SF            8
#define LORA_BW            125E3
#define LORA_TX_POWER      20
#define LORA_CCA_RSSI_DBM  (-90)    // limiar de channel sensing (RSSI do SX1276)
#define LORA_CCA_WINDOW_MS  1000
#define LORA_CCA_BACKOFF_MS 200

// Perfil regional de referencia (ver lib/src/band_plan.h).
// ATENCAO: valores de engenharia, nao parecer juridico. O operador deve
// confirmar o perfil e os limites vigentes na sua jurisdicao.
#define HEF_BAND_PROFILE   "915-ANATEL"

// Intervalo minimo entre ciclos de transmissao e o jitter aplicado
// (+/- LORA_TX_JITTER_PCT) para dessincronizar a frota (evita colisao
// quando varias unidades acordam juntas).
#define LORA_TX_INTERVAL_MIN_MS 30000UL
#define LORA_TX_JITTER_PCT      10
// Corrente de TX usada nas estimativas de energia (SX1276 @ 20 dBm).
#define LORA_TX_CURRENT_MA      120.0f

// ---------------------------------------------------------------
// Politica de TX adaptativa (v5.1.0, item 1.3 do plano)
// ---------------------------------------------------------------
// A v5.0.0 transmitia PERIODICAMENTE: um frame a cada 30 s, sem
// importar se o alvo tinha se movido. Agora a transmissao e' por
// EVENTO: a posicao alterou mais que LORA_MIN_MOVE_M **ou** passou
// LORA_HEARTBEAT_TX_MS desde a ultima transmissao.
//
// O heartbeat e' indispensavel: sem ele, um alvo PARADO seria
// indistinguivel de um alvo que saiu de campo (ou ficou sem bateria).
//
// O piso LORA_TX_INTERVAL_MIN_MS continua valendo: um alvo em
// movimento perpetuo nao pode inundar o enlace.
#define LORA_MIN_MOVE_M          10.0f    // limiar de movimento (metros)
#define LORA_HEARTBEAT_TX_MS     60000UL  // heartbeat maximo sem transmitir

// Retentativas: 1 retry por evento (1 transmissao original + 1 retry
// = 2 frames). A v5.0.0 fazia ate 3 transmissoes por evento.
#define LORA_TX_MAX_RETRIES      1

// ---------------------------------------------------------------
// Beacon FM (Si4713) - v5.1.0
// ---------------------------------------------------------------
// O beacon e' um transmissor COM CONTINUO: dezenas de mA enquanto esta
// em ON. Por isso ele tem duty cycle PROPRIO (independente do link
// LoRa) e corte automatico por bateria.
//
// O corte por bateria tem prioridade sobre a telemetria: preservar o
// link LoRa (que e' o que mantem a base ciente da unidade) vale mais
// que um beacon audivel.
#define FM_BEACON_ON_MS           3000UL   // 3 s ligado
#define FM_BEACON_OFF_MS         27000UL   // 27 s desligado -> 10% de duty
#define FM_BEACON_MIN_BATTERY_PCT  20      // abaixo disso: beacon desliga

// ============================================================
// GPS
// ============================================================
// v5.1.0: removido `GPS_POLL_INTERVAL_MS` (1000 ms).
//
//   A constante era enganosa: NAO controlava nenhuma leitura do GPS. O
//   Node 1 drena a UART do GNSS CONTINUAMENTE no loop principal
//   (`while (gpsSerial.available()) gps.encode(...)`), e o modulo GNSS
//   decide a propria taxa de saida (1 Hz por padrao). O que a constante
//   controlava, na pratica, era o INTERVALO DE TRANSMISSAO do link LoRa
//   (o `if (now - lastTxMs >= GPS_POLL_INTERVAL_MS)`), que e' agora
//   governado por `LORA_TX_INTERVAL_MIN_MS` + o orcamento de duty cycle.
//
//   Como o radio consumia mais que o GNSS, o gargalo real era o radio.
//   Manter uma constante morta e enganosa num arquivo que se declara
//   "fonte unica de verdade" e' pior que remove-la.
//
//   A validade do fix continua governada pela idade do ultimo fix
//   (`GPS_FIX_MAX_AGE_MS`), que independe da taxa de leitura.
#define GPS_FIX_MAX_AGE_MS     5000
#define GPS_MIN_SATS           4

// ============================================================
// SI4735 - receptor de banda de radiodifusao
// ============================================================
#define SI4735_I2C_ADDR     0x11
#define SI4735_SETTLE_MS    60      // settle minimo apos tuning
#define SWEEP_DWELL_MS      90      // tempo por ponto da varredura
#define SWEEP_MAX_POINTS    256     // pontos por varredura
#define SPECTRUM_RING       256

// ============================================================
// SESSOES / AUTENTICACAO / RATE LIMIT
// ============================================================
#define HTTP_SESSION_SLOTS          4
#define HTTP_SESSION_IDLE_MS        900000UL   // 15 min
#define HTTP_SESSION_ABSOLUTE_MS    14400000UL // 4 h
#define HTTP_TOKEN_HEX_LEN          64         // 32 bytes -> 64 hex
#define CLI_SESSION_IDLE_MS         300000UL   // 5 min
#define CLI_SESSION_ABSOLUTE_MS     1800000UL  // 30 min
#define MAX_AUTH_ATTEMPTS           5
#define BLOCK_DURATION_MS           1800000UL  // 30 min
#define MAX_BLOCKED_IPS             16
#define RATE_MAX_CLIENTS            16
#define RATE_LOGIN_BUCKET           5          // tentativas / janela
#define RATE_LOGIN_WINDOW_MS        60000UL
#define RATE_CMD_BUCKET             60         // comandos / janela
#define RATE_CMD_WINDOW_MS          60000UL
#define RATE_CMD_COOLDOWN_MS        50

// ============================================================
// VAULT / NVS
// ============================================================
#define HEF_NVS_NAMESPACE   "hef"
#define HEF_NVS_KEY_VAULT   "vault"
#define HEF_NVS_KEY_NODE    "nodeid"
#define HEF_VAULT_MAGIC     0x48464643   // "HFFC"
#define HEF_VAULT_VERSION   5
#define HEF_VAULT_BUF       512         // tamanho maximo do blob NVS
#define HEF_VAULT_HEADER_LEN 36         // magic+version+flags+len+iv+reservado
#define HEF_MAX_ENROLLMENTS 8
#define HEF_TOTP_SECRET_MAX 32
#define HEF_KEY_ID_MAX      255

// Capacidade do plaintext do vault (TLV) = blob - header - tag GCM.
// O vault falha FECHADO quando o conteudo nao cabe: descartar uma entrada
// em silencio seria uma falha de seguranca (o par perderia o epoch
// persistido e o replay pos-reboot voltaria a ser aceito).
#define HEF_VAULT_MAX_PLAIN (HEF_VAULT_BUF - HEF_VAULT_HEADER_LEN - HEF_TAG_LEN)

// Persistencia do estado anti-replay por par (epoch + high-water).
// Mudanca de epoch e' persistida IMEDIATAMENTE (e' o que fecha o replay
// pos-reboot do receptor). O contador high-water e' persistido no maximo
// a cada HEF_PEER_STATE_FLUSH_MS: 60 s => 1440 escritas/dia no NVS
// (~6 anos de endurance com o wear-leveling do NVS do ESP32).
// O intervalo e' o limite do risco residual: apos um reinicio, um replay
// de frame do MESMO epoch com contador ate HEF_PEER_STATE_FLUSH_MS atras
// ainda pode ser aceito. Replay de epoch ANTERIOR e' sempre rejeitado.
#define HEF_PEER_STATE_FLUSH_MS 60000UL

// ============================================================
// CAUSA DE REINICIO / WATCHDOG (v5.1.0, item 1.4)
// ============================================================
// Namespace NVS proprio para os contadores de reinicio. NAO e' o vault
// cifrado: contadores de operacao nao sao segredo, e o vault e'
// reescrito INTEIRO a cada gravacao — caro demais para um contador.
#define HEF_NVS_NAMESPACE_RESET "hefrst"
#define HEF_NVS_KEY_RESET      "counters"

// Chave da intencao do reinicio (gravada antes de `ESP.restart()`).
// E' consumida no boot seguinte e removida: uma intencao nao
// consumida seria reexibida em todos os boots seguintes, dizendo
// "reinicio solicitado pelo operador" em reinicios que foram
// travamentos.
#define HEF_NVS_KEY_RESET_INTENT "intent"

// Quantos boots podem acontecer sem gravar o estado na NVS.
//
// Cada gravacao na NVS consome vida util da particao. Numa operacao
// normal isso e' irrelevante. Mas num LACO DE BROWNOUT — a
// alimentacao oscila e o dispositivo reinicia 50 vezes por hora — a
// NVS sufferia 438 mil escritas por ano.
//
// A gravacao imediata so acontece quando a CAUSA MUDOU (um brownout
// depois de um boot normal e' evento novo e relevante) ou a cada
// `HEF_RESET_PERSIST_EVERY_BOOTS` boots. O resto fica em RAM e e'
// gravado no flush periodico.
#define HEF_RESET_PERSIST_EVERY_BOOTS 10UL

// Flush periodico do estado de reinicio (ms). Garante que os
// contadores acumulados em RAM sejam persistidos mesmo sem mudanca de
// causa.
#define HEF_RESET_FLUSH_MS 300000UL

// Timeout do watchdog de tarefa (segundos). O plano pede 30 s: um
// travamento do loop principal tem de derrubar o dispositivo em MENOS
// de 30 s, com a causa visivel.
#define HEF_WDT_TIMEOUT_S 30

// Quantas alimentacoes do WDT por janela de timeout, nas operacoes
// longas (SD, exportacao de log, sweep).
#define HEF_WDT_FEED_DIVISOR 3

// ============================================================
// LOG FORENSE (Node3)
// ============================================================
#define HEF_LOG_MAGIC       0x484C4735   // "HLG5"
#define HEF_LOG_BUFFER      256
#define HEF_HASH_LEN        32
#define HEF_CAPTURE_RING    64
#define HEF_UART_BUF        1024
#define HEF_SD_SPI_HZ       10000000

// ============================================================
// IDENTIFICACAO DE NO
// ============================================================
// node_id = 16 bits derivados do efuse MAC (unicidade por chip).
// O node_id e' estavel e permitire que o Node2 diferencie emissores.

#endif // HEFESTOS_PINS_H
