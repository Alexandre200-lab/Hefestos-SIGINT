#ifndef HEFESTOS_PINS_H
#define HEFESTOS_PINS_H

// ============================================================
// HEFESTOS SIGINT v4.0 — Centralized Pin/Config Definitions
// ============================================================

// === Node1 (Transmissor/Alvo - ESP32) ===
#define N1_LORA_SS      5
#define N1_LORA_RST     14
#define N1_LORA_DIO0    26
#define N1_FM_RST       32
#define N1_GPS_RX       16
#define N1_GPS_TX       17
#define N1_RF_SWITCH    25

// === Node2 (Base Hefestos - ESP32) ===
#define N2_LORA_SS      5
#define N2_LORA_RST     14
#define N2_LORA_DIO0    26
#define N2_RX_RST       12
#define N2_UART_TX      17
#define N2_UART_RX      16
#define N2_I2C_SDA      21
#define N2_I2C_SCL      22

// === Node3 (Caixa Preta - ESP32-C3) ===
#define N3_SD_CS        4
#define N3_SD_MOSI      6
#define N3_SD_MISO      5
#define N3_SD_SCK       7
#define N3_UART_RX      20
#define N3_UART_TX      21
#define N3_LED_GREEN    7
#define N3_LED_RED      8
#define N3_BUZZER       9

// === EEPROM Map (unificado v4.0) ===
#define EEPROM_SIZE         512
#define EEPROM_MAGIC        0x4848
#define EEPROM_ADDR_MAGIC       0x000
#define EEPROM_ADDR_VERSION     0x002
#define EEPROM_ADDR_FLAGS       0x003
#define EEPROM_ADDR_AES_KEY     0x004
#define EEPROM_ADDR_IV          0x014
#define EEPROM_ADDR_WIFI_PASS   0x024
#define EEPROM_ADDR_CLI_PASS    0x044
#define EEPROM_ADDR_CLI_USER    0x064
#define EEPROM_ADDR_COUNTER     0x100
#define EEPROM_ADDR_BLOCKED     0x110

// === Fixed Buffer Sizes ===
#define CLI_USER_SIZE       16
#define CLI_PASS_SIZE       32
#define WIFI_PASS_SIZE      32
#define AES_KEY_SIZE        16
#define AES_IV_SIZE         16
#define GCM_IV_SIZE         12
#define GCM_KEY_SIZE        16
#define GCM_TAG_SIZE        16
#define GCM_PAYLOAD_MAX     240
#define SECURE_STORAGE_KEY_SIZE 32
#define SECURE_STORAGE_IV_SIZE  12
#define SECURE_STORAGE_TAG_SIZE 16
#define SECURE_STORAGE_BLOCK    16

// === LoRa Configuration ===
#define LORA_FREQ          915E6
#define LORA_SF            10
#define LORA_BW            125E3
#define LORA_TX_POWER      20

// === Timing ===
#define GPS_POLL_INTERVAL      1000
#define TX_SAVE_INTERVAL       10
#define SESSION_IDLE_TIMEOUT   60000
#define SESSION_ABSOLUTE_TIMEOUT 300000
#define MAX_AUTH_ATTEMPTS      3
#define BLOCK_DURATION         1800000
#define MAX_BLOCKED_IPS        16

// === Flags ===
#define FLAG_DEBUG_MODE       0x01
#define FLAG_FACTORY_RESET    0x02
#define FLAG_KEYS_GENERATED   0x04

#endif // HEFESTOS_PINS_H
