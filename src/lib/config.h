// config.h - EEPROM Configuration Manager - v2.1
// Gerencia credenciais, chaves criptográficas e parâmetros operacionais
// Suporta geração de chaves únicas no primeiro boot

#ifndef CONFIG_H
#define CONFIG_H

#include <EEPROM.h>
#include <string.h>
#include <ESP32/rom/rtc.h>
#include <WiFi.h>

#define EEPROM_SIZE 512
#define EEPROM_MAGIC 0x4845
#define EEPROM_MAGIC_V2 0x4846
#define EEPROM_ADDR_MAGIC 0
#define EEPROM_ADDR_VERSION 2
#define EEPROM_ADDR_AES_KEY 4
#define EEPROM_ADDR_AES_IV 20
#define EEPROM_ADDR_WIFI_PASS 36
#define EEPROM_ADDR_CLI_PASS 68
#define EEPROM_ADDR_FLAGS 100

#define AES_KEY_SIZE 16
#define AES_IV_SIZE 16
#define WIFI_PASS_SIZE 32
#define CLI_PASS_SIZE 32

#define FLAG_DEBUG_MODE 0x01
#define FLAG_FACTORY_RESET 0x02
#define FLAG_KEYS_GENERATED 0x04

struct HefestosConfig {
  uint16_t magic;
  uint8_t version;
  uint8_t flags;
  byte aes_key[AES_KEY_SIZE];
  byte aes_iv[AES_IV_SIZE];
  char wifi_pass[WIFI_PASS_SIZE];
  char cli_pass[CLI_PASS_SIZE];
};

class ConfigManager {
private:
  HefestosConfig config;
  bool initialized = false;

  void generateUniqueKeys() {
    uint32_t seed = 0;
    seed |= (ESP.getEfuseMac() >> 32) & 0xFFFFFFFF;
    seed ^= rtc_get_reset_reason(0);
    seed ^= ESP.getFreeHeap();
    seed ^= millis();

    for (int i = 0; i < AES_KEY_SIZE; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
      config.aes_key[i] = (seed >> (i % 8)) & 0xFF;
    }

    for (int i = 0; i < AES_IV_SIZE; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
      config.aes_iv[i] = (seed >> (i % 8)) & 0xFF;
    }

    config.flags |= FLAG_KEYS_GENERATED;
  }

  void generateSecurePassword(char* dest, int size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*";
    uint32_t seed = ESP.getEfuseMac();
    seed ^= millis();

    for (int i = 0; i < size - 1; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
      dest[i] = charset[seed % strlen(charset)];
    }
    dest[size - 1] = '\0';
  }

public:
  ConfigManager() {}

  void begin() {
    EEPROM.begin(EEPROM_SIZE);
    
    uint16_t magic = (EEPROM.read(EEPROM_ADDR_MAGIC) << 8) | EEPROM.read(EEPROM_ADDR_MAGIC + 1);
    
    if (magic != EEPROM_MAGIC && magic != EEPROM_MAGIC_V2) {
      loadDefaults();
      if ((config.flags & FLAG_KEYS_GENERATED) == 0) {
        generateUniqueKeys();
        generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
        generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
      }
      save();
    } else {
      load();
      if ((config.flags & FLAG_KEYS_GENERATED) == 0) {
        generateUniqueKeys();
        generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
        generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
        save();
      }
    }
    initialized = true;
  }

  void loadDefaults() {
    config.magic = EEPROM_MAGIC_V2;
    config.version = 2;
    config.flags = 0;
    
    const byte default_key[] = {0x48, 0x65, 0x66, 0x65, 0x73, 0x74, 0x6F, 0x73,
                                0x54, 0x61, 0x63, 0x74, 0x69, 0x63, 0x61, 0x00};
    const byte default_iv[] = {0x56, 0x65, 0x74, 0x6F, 0x72, 0x49, 0x6E, 0x69,
                               0x63, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x61, 0x64};
    
    memcpy(config.aes_key, default_key, AES_KEY_SIZE);
    memcpy(config.aes_iv, default_iv, AES_IV_SIZE);
    strncpy(config.wifi_pass, "Hefestos2024!SecureNet", WIFI_PASS_SIZE - 1);
    strncpy(config.cli_pass, "HefestosTactical@2024", CLI_PASS_SIZE - 1);
  }

  void load() {
    config.magic = (EEPROM.read(EEPROM_ADDR_MAGIC) << 8) | EEPROM.read(EEPROM_ADDR_MAGIC + 1);
    config.version = EEPROM.read(EEPROM_ADDR_VERSION);
    config.flags = EEPROM.read(EEPROM_ADDR_FLAGS);
    
    for (int i = 0; i < AES_KEY_SIZE; i++) {
      config.aes_key[i] = EEPROM.read(EEPROM_ADDR_AES_KEY + i);
    }
    for (int i = 0; i < AES_IV_SIZE; i++) {
      config.aes_iv[i] = EEPROM.read(EEPROM_ADDR_AES_IV + i);
    }
    
    for (int i = 0; i < WIFI_PASS_SIZE; i++) {
      config.wifi_pass[i] = EEPROM.read(EEPROM_ADDR_WIFI_PASS + i);
    }
    
    for (int i = 0; i < CLI_PASS_SIZE; i++) {
      config.cli_pass[i] = EEPROM.read(EEPROM_ADDR_CLI_PASS + i);
    }
  }

  void save() {
    EEPROM.write(EEPROM_ADDR_MAGIC, (config.magic >> 8) & 0xFF);
    EEPROM.write(EEPROM_ADDR_MAGIC + 1, config.magic & 0xFF);
    EEPROM.write(EEPROM_ADDR_VERSION, config.version);
    EEPROM.write(EEPROM_ADDR_FLAGS, config.flags);
    
    for (int i = 0; i < AES_KEY_SIZE; i++) {
      EEPROM.write(EEPROM_ADDR_AES_KEY + i, config.aes_key[i]);
    }
    for (int i = 0; i < AES_IV_SIZE; i++) {
      EEPROM.write(EEPROM_ADDR_AES_IV + i, config.aes_iv[i]);
    }
    
    for (int i = 0; i < WIFI_PASS_SIZE; i++) {
      EEPROM.write(EEPROM_ADDR_WIFI_PASS + i, config.wifi_pass[i]);
    }
    for (int i = 0; i < CLI_PASS_SIZE; i++) {
      EEPROM.write(EEPROM_ADDR_CLI_PASS + i, config.cli_pass[i]);
    }
    
    EEPROM.commit();
  }

  byte* getAESKey() { return config.aes_key; }
  byte* getAESIV() { return config.aes_iv; }
  const char* getWiFiPassword() { return config.wifi_pass; }
  const char* getCLIPassword() { return config.cli_pass; }
  uint8_t getFlags() { return config.flags; }
  
  bool isDebugMode() { return config.flags & FLAG_DEBUG_MODE; }
  bool keysGenerated() { return config.flags & FLAG_KEYS_GENERATED; }

  void setAESKey(byte* key, int len) {
    if (len == AES_KEY_SIZE) {
      memcpy(config.aes_key, key, AES_KEY_SIZE);
      config.flags |= FLAG_KEYS_GENERATED;
      save();
    }
  }

  void setWiFiPassword(const char* pass) {
    if (strlen(pass) >= 12) {
      strncpy(config.wifi_pass, pass, WIFI_PASS_SIZE - 1);
      save();
    }
  }

  void setCLIPassword(const char* pass) {
    if (strlen(pass) >= 12) {
      strncpy(config.cli_pass, pass, CLI_PASS_SIZE - 1);
      save();
    }
  }

  void setDebugMode(bool enabled) {
    if (enabled) config.flags |= FLAG_DEBUG_MODE;
    else config.flags &= ~FLAG_DEBUG_MODE;
    save();
  }

  void factoryReset() {
    memset(&config, 0, sizeof(config));
    config.magic = EEPROM_MAGIC_V2;
    config.version = 2;
    generateUniqueKeys();
    generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
    generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
    save();
  }

  bool isInitialized() { return initialized; }
};

#endif // CONFIG_H