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
#define HEF_FW_VERSION_MINOR 0
#define HEF_FW_VERSION_PATCH 0
#define HEF_FW_VERSION_STR "5.0.0"

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

// ============================================================
// LORA
// ============================================================
#define LORA_FREQ          915E6
#define LORA_SF            10
#define LORA_BW            125E3
#define LORA_TX_POWER      20
#define LORA_CCA_RSSI_DBM  (-90)    // limiar de channel sensing (RSSI do SX1276)
#define LORA_CCA_WINDOW_MS  1000
#define LORA_CCA_BACKOFF_MS 200

// ============================================================
// GPS
// ============================================================
#define GPS_POLL_INTERVAL_MS   1000
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
#define HEF_MAX_ENROLLMENTS 8
#define HEF_TOTP_SECRET_MAX 32
#define HEF_KEY_ID_MAX      255

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
