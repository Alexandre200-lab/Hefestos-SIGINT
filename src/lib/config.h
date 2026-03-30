// config.h - EEPROM Configuration Manager
// Gerencia credenciais, chaves criptográficas e parâmetros operacionais de forma segura

#ifndef CONFIG_H
#define CONFIG_H

#include <EEPROM.h>
#include <string.h>

// EEPROM Layout
#define EEPROM_SIZE 512
#define EEPROM_MAGIC 0x4845 // "HE" magic bytes
#define EEPROM_ADDR_MAGIC 0
#define EEPROM_ADDR_VERSION 2
#define EEPROM_ADDR_AES_KEY 4
#define EEPROM_ADDR_AES_IV 20
#define EEPROM_ADDR_WIFI_PASS 36
#define EEPROM_ADDR_CLI_PASS 68
#define EEPROM_ADDR_FLAGS 100

// Tamanhos
#define AES_KEY_SIZE 16
#define AES_IV_SIZE 16
#define WIFI_PASS_SIZE 32
#define CLI_PASS_SIZE 32

// Flags
#define FLAG_DEBUG_MODE 0x01
#define FLAG_FACTORY_RESET 0x02

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

public:
  ConfigManager() {}

  // Inicializa EEPROM na primeira execução
  void begin() {
    EEPROM.begin(EEPROM_SIZE);
    
    uint16_t magic = (EEPROM.read(EEPROM_ADDR_MAGIC) << 8) | EEPROM.read(EEPROM_ADDR_MAGIC + 1);
    
    if (magic != EEPROM_MAGIC) {
      loadDefaults();
      save();
    } else {
      load();
    }
    initialized = true;
  }

  // Carrega valores padrão seguros
  void loadDefaults() {
    config.magic = EEPROM_MAGIC;
    config.version = 1;
    config.flags = 0;
    
    // Chaves padrão (DEVE ser alterado em produção!)
    const byte default_key[] = {0x48, 0x65, 0x66, 0x65, 0x73, 0x74, 0x6F, 0x73,
                                0x54, 0x61, 0x63, 0x74, 0x69, 0x63, 0x61, 0x00}; // "HefestosTactica\0"
    const byte default_iv[] = {0x56, 0x65, 0x74, 0x6F, 0x72, 0x49, 0x6E, 0x69,
                               0x63, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x61, 0x64}; // "VetorInicializado"
    
    memcpy(config.aes_key, default_key, AES_KEY_SIZE);
    memcpy(config.aes_iv, default_iv, AES_IV_SIZE);
    
    // Senhas padrão (STRONG - mínimo 12 caracteres)
    strncpy(config.wifi_pass, "Hefestos2024!SecureNet", WIFI_PASS_SIZE - 1);
    strncpy(config.cli_pass, "HefestosTactical@2024", CLI_PASS_SIZE - 1);
  }

  // Carrega EEPROM para RAM
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
    
    char* p_wifi = config.wifi_pass;
    for (int i = 0; i < WIFI_PASS_SIZE; i++) {
      p_wifi[i] = EEPROM.read(EEPROM_ADDR_WIFI_PASS + i);
    }
    
    char* p_cli = config.cli_pass;
    for (int i = 0; i < CLI_PASS_SIZE; i++) {
      p_cli[i] = EEPROM.read(EEPROM_ADDR_CLI_PASS + i);
    }
  }

  // Salva configuração em EEPROM
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

  // Getters com segurança
  byte* getAESKey() { return config.aes_key; }
  byte* getAESIV() { return config.aes_iv; }
  const char* getWiFiPassword() { return config.wifi_pass; }
  const char* getCLIPassword() { return config.cli_pass; }
  uint8_t getFlags() { return config.flags; }
  
  bool isDebugMode() { return config.flags & FLAG_DEBUG_MODE; }

  // Setters com validação
  void setAESKey(byte* key, int len) {
    if (len == AES_KEY_SIZE) {
      memcpy(config.aes_key, key, AES_KEY_SIZE);
      save();
    }
  }

  void setWiFiPassword(const char* pass) {
    if (strlen(pass) >= 12) { // Mínimo 12 caracteres
      strncpy(config.wifi_pass, pass, WIFI_PASS_SIZE - 1);
      save();
    }
  }

  void setCLIPassword(const char* pass) {
    if (strlen(pass) >= 12) { // Mínimo 12 caracteres
      strncpy(config.cli_pass, pass, CLI_PASS_SIZE - 1);
      save();
    }
  }

  void setDebugMode(bool enabled) {
    if (enabled) {
      config.flags |= FLAG_DEBUG_MODE;
    } else {
      config.flags &= ~FLAG_DEBUG_MODE;
    }
    save();
  }

  // Factory reset
  void factoryReset() {
    loadDefaults();
    save();
  }

  bool isInitialized() { return initialized; }
};

#endif // CONFIG_H
