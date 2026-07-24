// config.h - EEPROM Configuration Manager - v4.0
// Gerencia credenciais, chaves criptográficas e parâmetros operacionais
// EEPROM criptografada com chave derivada do efuse MAC (único por chip)

#ifndef CONFIG_H
#define CONFIG_H

#include <EEPROM.h>
#include <string.h>
#include <esp_random.h>
#include <WiFi.h>
#include <esp_efuse.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/gcm.h>
#include "hefestos_pins.h"

// Legacy magic numbers for backward compatibility
#define EEPROM_MAGIC_V2 0x4846
#define EEPROM_MAGIC_V3 0x4847

// Encrypted EEPROM layout:
// [0-1]: magic (0x4848)
// [2]: version (4)
// [3]: flags
// [4-15]: IV (12 bytes) for GCM
// [16-31]: auth tag (16 bytes)
// [32+]: ciphertext (config struct encrypted)

struct HefestosConfig {
  uint16_t magic;
  uint8_t version;
  uint8_t flags;
  uint8_t aes_key[AES_KEY_SIZE];
  uint8_t aes_iv[AES_IV_SIZE];
  char wifi_pass[WIFI_PASS_SIZE];
  char cli_pass[CLI_PASS_SIZE];
  char cli_user[CLI_USER_SIZE];
};

class ConfigManager {
private:
  HefestosConfig config;
  bool initialized = false;
  uint8_t master_key[SECURE_STORAGE_KEY_SIZE];

  void deriveMasterKey() {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    
    const unsigned char salt[] = "Hefestos-v4-EEPROM";
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
        mac, sizeof(mac),
        salt, sizeof(salt) - 1,
        100000,
        SECURE_STORAGE_KEY_SIZE, master_key);
    mbedtls_md_free(&md_ctx);
  }

  bool encryptConfig(uint8_t* output, size_t* out_len) {
    uint8_t iv[SECURE_STORAGE_IV_SIZE];
    esp_fill_random(iv, SECURE_STORAGE_IV_SIZE);
    
    size_t plain_len = sizeof(HefestosConfig);
    uint8_t tag[SECURE_STORAGE_TAG_SIZE];
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, master_key, 256);
    if (ret != 0) { mbedtls_gcm_free(&ctx); return false; }
    
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
        plain_len, iv, SECURE_STORAGE_IV_SIZE, NULL, 0,
        (unsigned char*)&config, output + SECURE_STORAGE_IV_SIZE + SECURE_STORAGE_TAG_SIZE,
        SECURE_STORAGE_TAG_SIZE, tag);
    mbedtls_gcm_free(&ctx);
    
    if (ret != 0) return false;
    
    memcpy(output, iv, SECURE_STORAGE_IV_SIZE);
    memcpy(output + SECURE_STORAGE_IV_SIZE, tag, SECURE_STORAGE_TAG_SIZE);
    *out_len = SECURE_STORAGE_IV_SIZE + SECURE_STORAGE_TAG_SIZE + plain_len;
    return true;
  }

  bool decryptConfig(const uint8_t* input, size_t in_len) {
    if (in_len < SECURE_STORAGE_IV_SIZE + SECURE_STORAGE_TAG_SIZE + sizeof(HefestosConfig)) {
      return false;
    }
    
    const uint8_t* iv = input;
    const uint8_t* tag = input + SECURE_STORAGE_IV_SIZE;
    const uint8_t* ciphertext = input + SECURE_STORAGE_IV_SIZE + SECURE_STORAGE_TAG_SIZE;
    size_t cipher_len = in_len - SECURE_STORAGE_IV_SIZE - SECURE_STORAGE_TAG_SIZE;
    
    if (cipher_len != sizeof(HefestosConfig)) return false;
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, master_key, 256);
    if (ret != 0) { mbedtls_gcm_free(&ctx); return false; }
    
    ret = mbedtls_gcm_auth_decrypt(&ctx, cipher_len,
        iv, SECURE_STORAGE_IV_SIZE, NULL, 0,
        tag, SECURE_STORAGE_TAG_SIZE, ciphertext, (unsigned char*)&config);
    mbedtls_gcm_free(&ctx);
    
    return ret == 0;
  }

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

  void loadDefaults() {
    config.magic = EEPROM_MAGIC;
    config.version = 4;
    config.flags = 0;
    generateUniqueKeys();
    generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
    generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
    strncpy(config.cli_user, "admin", CLI_USER_SIZE - 1);
  }

  void loadEncrypted() {
    size_t total_size = EEPROM_SIZE - EEPROM_ADDR_MAGIC;
    uint8_t* buffer = new uint8_t[total_size];
    
    for (size_t i = 0; i < total_size; i++) {
      buffer[i] = EEPROM.read(EEPROM_ADDR_MAGIC + i);
    }
    
    if (!decryptConfig(buffer + 4, total_size - 4)) {
      delete[] buffer;
      debug.logError("EEPROM decrypt failed - wrong chip or corrupted data");
      loadDefaults();
      save();
      return;
    }
    
    delete[] buffer;
  }

  void saveEncrypted() {
    uint8_t output[EEPROM_SIZE];
    size_t out_len;
    
    config.magic = EEPROM_MAGIC;
    config.version = 4;
    
    if (!encryptConfig(output + 4, &out_len)) {
      debug.logError("EEPROM encrypt failed");
      return;
    }
    
    output[0] = (EEPROM_MAGIC >> 8) & 0xFF;
    output[1] = EEPROM_MAGIC & 0xFF;
    output[2] = config.version;
    output[3] = config.flags;
    
    size_t total_written = 4 + out_len;
    for (size_t i = 0; i < total_written; i++) {
      EEPROM.write(EEPROM_ADDR_MAGIC + i, output[i]);
    }
    EEPROM.commit();
  }

public:
  ConfigManager() {}

  void begin() {
    deriveMasterKey();
    EEPROM.begin(EEPROM_SIZE);
    
    uint16_t magic = (EEPROM.read(EEPROM_ADDR_MAGIC) << 8) | EEPROM.read(EEPROM_ADDR_MAGIC + 1);
    
    if (magic != EEPROM_MAGIC && magic != EEPROM_MAGIC_V2 && magic != EEPROM_MAGIC_V3) {
      loadDefaults();
      if ((config.flags & FLAG_KEYS_GENERATED) == 0) {
        generateUniqueKeys();
        generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
        generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
      }
      saveEncrypted();
    } else if (magic == EEPROM_MAGIC) {
      loadEncrypted();
      if ((config.flags & FLAG_KEYS_GENERATED) == 0) {
        generateUniqueKeys();
        generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
        generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
        saveEncrypted();
      }
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
    
    for (int i = 0; i < CLI_USER_SIZE; i++) {
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
    for (int i = 0; i < CLI_USER_SIZE; i++) {
      EEPROM.write(EEPROM_ADDR_CLI_USER + i, config.cli_user[i]);
    }
    
    EEPROM.commit();
  }

  const uint8_t* getAESKey() const { return config.aes_key; }
  const uint8_t* getAESIV() const { return config.aes_iv; }
  const char* getWiFiPassword() { return config.wifi_pass; }
  const char* getCLIPassword() { return config.cli_pass; }
  const char* getCLIUsername() { return config.cli_user; }
  uint8_t getFlags() { return config.flags; }
  
  bool isDebugMode() { return config.flags & FLAG_DEBUG_MODE; }
  bool keysGenerated() { return config.flags & FLAG_KEYS_GENERATED; }

  void setAESKey(uint8_t* key, int len) {
    if (len == AES_KEY_SIZE) {
      memcpy(config.aes_key, key, AES_KEY_SIZE);
      config.flags |= FLAG_KEYS_GENERATED;
      saveEncrypted();
    }
  }

  void setWiFiPassword(const char* pass) {
    if (strlen(pass) >= 12) {
      strncpy(config.wifi_pass, pass, WIFI_PASS_SIZE - 1);
      saveEncrypted();
    }
  }

  void setCLIPassword(const char* pass) {
    if (strlen(pass) >= 12) {
      strncpy(config.cli_pass, pass, CLI_PASS_SIZE - 1);
      saveEncrypted();
    }
  }

  void setCLIUsername(const char* user) {
    if (strlen(user) >= 3 && strlen(user) < CLI_USER_SIZE) {
      strncpy(config.cli_user, user, CLI_USER_SIZE - 1);
      saveEncrypted();
    }
  }

  void setDebugMode(bool enabled) {
    if (enabled) config.flags |= FLAG_DEBUG_MODE;
    else config.flags &= ~FLAG_DEBUG_MODE;
    saveEncrypted();
  }

  void factoryReset() {
    memset(&config, 0, sizeof(config));
    config.magic = EEPROM_MAGIC;
    config.version = 4;
    generateUniqueKeys();
    generateSecurePassword(config.wifi_pass, WIFI_PASS_SIZE);
    generateSecurePassword(config.cli_pass, CLI_PASS_SIZE);
    strncpy(config.cli_user, "hefestos", CLI_USER_SIZE - 1);
    saveEncrypted();
  }

  void dumpKeys() {
    debug.log("=== HEFESTOS KEY DUMP ===");
    debug.log("Use these to recover if chip is replaced:");
    debug.logf("MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
        (uint8_t)(master_key[0]), (uint8_t)(master_key[1]), (uint8_t)(master_key[2]),
        (uint8_t)(master_key[3]), (uint8_t)(master_key[4]), (uint8_t)(master_key[5]));
    debug.logf("AES Key SHA256: [computed from master_key]");
    debug.logf("WiFi Pass: %s", config.wifi_pass);
    debug.logf("CLI User: %s", config.cli_user);
    debug.logf("CLI Pass: %s", config.cli_pass);
    debug.logf("TOTP Secret: [check totp_auth.h]");
  }

  bool isInitialized() { return initialized; }
};

#endif // CONFIG_H