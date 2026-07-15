// config.h - EEPROM Configuration Manager - v3.0
// Gerencia credenciais, chaves criptográficas e parâmetros operacionais
// Suporta geração de chaves únicas no primeiro boot
// CORRIGIDO v3.0: Username configurável (não mais hardcoded)

#ifndef CONFIG_H
#define CONFIG_H

#include <EEPROM.h>
#include <string.h>
#include <esp_random.h>
#include <WiFi.h>

#define EEPROM_SIZE 512
#define EEPROM_MAGIC 0x4845
#define EEPROM_MAGIC_V2 0x4846
#define EEPROM_MAGIC_V3 0x4847  // Nova versão v3.0
#define EEPROM_ADDR_MAGIC 0
#define EEPROM_ADDR_VERSION 2
#define EEPROM_ADDR_AES_KEY 4
#define EEPROM_ADDR_AES_IV 20
#define EEPROM_ADDR_WIFI_PASS 36
#define EEPROM_ADDR_CLI_PASS 68
#define EEPROM_ADDR_CLI_USER 100  // NOVO v3.0: Username
#define EEPROM_ADDR_FLAGS 132

#define AES_KEY_SIZE 16
#define AES_IV_SIZE 16
#define WIFI_PASS_SIZE 32
#define CLI_PASS_SIZE 32
#define CLI_USER_SIZE 16         // NOVO v3.0

#define FLAG_DEBUG_MODE 0x01
#define FLAG_FACTORY_RESET 0x02
#define FLAG_KEYS_GENERATED 0x04

struct HefestosConfig {
  uint16_t magic;
  uint8_t version;
  uint8_t flags;
  uint8_t aes_key[AES_KEY_SIZE];
  uint8_t aes_iv[AES_IV_SIZE];
  char wifi_pass[WIFI_PASS_SIZE];
  char cli_pass[CLI_PASS_SIZE];
  char cli_user[CLI_USER_SIZE];  // NOVO v3.0
};

class ConfigManager {
private:
  HefestosConfig config;
  bool initialized = false;

  void generateUniqueKeys() {
    esp_fill_random(config.aes_key, AES_KEY_SIZE);
    esp_fill_random(config.aes_iv, AES_IV_SIZE);
    config.flags |= FLAG_KEYS_GENERATED;
  }

  void generateSecurePassword(char* dest, int size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*";
    int charset_len = strlen(charset);
    uint8_t rand_buf[64];
    int needed = size - 1;
    int offset = 0;
    while (needed > 0) {
      int chunk = needed < (int)sizeof(rand_buf) ? needed : (int)sizeof(rand_buf);
      esp_fill_random(rand_buf, chunk);
      for (int i = 0; i < chunk; i++) {
        dest[offset++] = charset[rand_buf[i] % charset_len];
      }
      needed -= chunk;
    }
    dest[size - 1] = '\0';
  }

public:
  ConfigManager() {}

  void begin() {
    EEPROM.begin(EEPROM_SIZE);
    
    uint16_t magic = (EEPROM.read(EEPROM_ADDR_MAGIC) << 8) | EEPROM.read(EEPROM_ADDR_MAGIC + 1);
    
    if (magic != EEPROM_MAGIC && magic != EEPROM_MAGIC_V2 && magic != EEPROM_MAGIC_V3) {
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
    config.magic = EEPROM_MAGIC_V3;
    config.version = 3;
    config.flags = 0;
    generateUniqueKeys();
    generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
    generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
    strncpy(config.cli_user, "admin", CLI_USER_SIZE - 1);
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
    
    for (int i = 0; i < CLI_USER_SIZE; i++) {  // v3.0
      config.cli_user[i] = EEPROM.read(EEPROM_ADDR_CLI_USER + i);
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
    for (int i = 0; i < CLI_USER_SIZE; i++) {  // v3.0
      EEPROM.write(EEPROM_ADDR_CLI_USER + i, config.cli_user[i]);
    }
    
    EEPROM.commit();
  }

  uint8_t* getAESKey() { return config.aes_key; }
  uint8_t* getAESIV() { return config.aes_iv; }
  const char* getWiFiPassword() { return config.wifi_pass; }
  const char* getCLIPassword() { return config.cli_pass; }
  const char* getCLIUsername() { return config.cli_user; }  // NOVO v3.0
  uint8_t getFlags() { return config.flags; }
  
  bool isDebugMode() { return config.flags & FLAG_DEBUG_MODE; }
  bool keysGenerated() { return config.flags & FLAG_KEYS_GENERATED; }

  void setAESKey(uint8_t* key, int len) {
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

  void setCLIUsername(const char* user) {  // NOVO v3.0
    if (strlen(user) >= 3 && strlen(user) < CLI_USER_SIZE) {
      strncpy(config.cli_user, user, CLI_USER_SIZE - 1);
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
    config.magic = EEPROM_MAGIC_V3;  // v3.0
    config.version = 3;
    generateUniqueKeys();
    generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
    generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
    strncpy(config.cli_user, "hefestos", CLI_USER_SIZE - 1);  // v3.0: Novo user diferente
    save();
  }

  bool isInitialized() { return initialized; }
};

#endif // CONFIG_H