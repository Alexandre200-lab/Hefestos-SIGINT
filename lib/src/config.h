// config.h - Vault de configuracao cifrado em NVS - v5.0.0
//
// REESCRITO do zero em relacao a v4.x.
//
// Bugs criticos da v4.x corrigidos aqui:
//   1) decryptConfig() exigia cipher_len == sizeof(struct) (116 bytes),
//      mas loadEncrypted() passava 508 bytes -> o decrypt SEMPRE falhava.
//      Consequencia: as credenciais eram gravadas em TEXTO PURO no layout
//      legacy e a chave AES era REGENERADA A CADA BOOT.
//   2) As flags de firmware (FLAG_FW_VERSION 0xF8 / FLAG_FW_MINOR 0x07)
//      colidiam com FLAG_KEYS_GENERATED (0x04) e FLAG_DEBUG_MODE (0x01),
//      haciendo o "SAFE MODE" disparar em todo boot.
//   3) PBKDF2 com 100k iteracoes sobre o MAC do efuse (que nao e senha
//      humana): primitiva incorreta. Substituido por HKDF-SHA256.
//
// Formato do vault (NVS, namespace "hef", key "vault"):
//   +---------------------------+
//   | magic    u32 LE           |  HEF_VAULT_MAGIC
//   | version  u8               |  HEF_VAULT_VERSION
//   | flags    u8               |
//   | totalLen u16 LE           |  tamanho do ciphertext
//   | iv       u8[12]           |
//   | tag      u8[16]           |
//   +---------------------------+
//   | ciphertext (TLV)          |  AES-256-GCM
//   +---------------------------+
//
// A chave do vault e' derivada do MAC do efuse (HKDF) => o vault e'
// vinculado ao chip. Trocar de ESP32 invalida o conteudo (propriedade
// desejada: anti-clonagem).
#ifndef HEF_CONFIG_H
#define HEF_CONFIG_H

#include <stdint.h>
#include <string.h>
#include <Preferences.h>
#include <esp_efuse.h>
#include <esp_system.h>
#include <mbedtls/md.h>

#include "hefestos_pins.h"
#include "crypto_gcm.h"
#include "debug.h"

#define HEF_TLV_WIFI_PASS 0x01
#define HEF_TLV_CLI_USER  0x02
#define HEF_TLV_CLI_PASS  0x03
#define HEF_TLV_TOTP      0x04
#define HEF_TLV_PSK       0x05
#define HEF_TLV_ENROLL    0x06
#define HEF_TLV_NODE_ID   0x07
#define HEF_TLV_TZ_MIN    0x08

#define HEF_FLAG_PROVISIONED 0x01
#define HEF_FLAG_DEBUG       0x02

struct HefEnrollment {
    uint16_t nodeId;
    uint8_t  keyId;
};

class ConfigVault {
private:
    Preferences prefs_;
    uint8_t vaultKey_[HEF_AEAD_KEY_LEN];
    uint8_t masterPsk_[HEF_KEY_LEN];
    bool    havePsk_;
    uint8_t flags_;
    uint16_t nodeId_;
    HefEnrollment enroll_[HEF_MAX_ENROLLMENTS];
    uint8_t enrollCount_;
    bool loaded_;

    // --- Derivacao da chave do vault a partir do MAC do efuse ---
    void deriveVaultKey() {
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        const uint8_t salt[] = "Hefestos-v5-vault";
        const uint8_t info[] = "hefestos-v5/vault/aes256";
        hefHkdfSha256(mac, sizeof(mac), salt, sizeof(salt) - 1,
                      info, sizeof(info) - 1, vaultKey_, sizeof(vaultKey_));
    }

    // --- Helpers TLV ---
    static size_t tlvAppend(uint8_t* buf, size_t cap, size_t pos,
                            uint8_t type, const uint8_t* val, size_t len) {
        if (pos + 3 + len > cap) return pos;
        buf[pos++] = type;
        buf[pos++] = (uint8_t)(len & 0xFF);
        buf[pos++] = (uint8_t)((len >> 8) & 0xFF);
        if (len && val) memcpy(buf + pos, val, len);
        return pos + len;
    }

    static bool tlvFind(const uint8_t* buf, size_t len, uint8_t type,
                        const uint8_t** out, size_t* outLen) {
        size_t pos = 0;
        while (pos + 3 <= len) {
            uint8_t  t   = buf[pos];
            uint16_t l   = (uint16_t)buf[pos + 1] | ((uint16_t)buf[pos + 2] << 8);
            size_t   hdr = 3;
            if (pos + hdr + l > len) return false;
            if (t == type) { *out = buf + pos + hdr; *outLen = l; return true; }
            pos += hdr + l;
        }
        return false;
    }

    void wipePsk() {
        volatile uint8_t* p = masterPsk_;
        for (size_t i = 0; i < sizeof(masterPsk_); i++) p[i] = 0;
        havePsk_ = false;
    }

public:
    ConfigVault()
        : havePsk_(false), flags_(0), nodeId_(0), enrollCount_(0), loaded_(false) {
        memset(masterPsk_, 0, sizeof(masterPsk_));
        memset(enroll_, 0, sizeof(enroll_));
    }

    // ---- Ciclo de vida ----

    bool begin() {
        deriveVaultKey();

        // node_id = 16 bits do MAC do efuse (estavel e unico por chip)
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        nodeId_ = (uint16_t)(((uint16_t)mac[4] << 8) | mac[5]);
        if (nodeId_ == 0) nodeId_ = 1;

        prefs_.begin(HEF_NVS_NAMESPACE, false);
        loaded_ = load();
        return true;
    }

    void end() {
        wipePsk();
        prefs_.end();
        loaded_ = false;
    }

    bool isLoaded() const { return loaded_; }

    // ---- Persistencia ----

    bool load() {
        havePsk_ = false;
        enrollCount_ = 0;
        flags_ = 0;

        size_t blobLen = prefs_.getBytesLength(HEF_NVS_KEY_VAULT);
        if (blobLen < 44) return false;   // header(4+1+1+2+12+16)=36 + 1 tag? -> minimo 36
        if (blobLen > 2048) return false;

        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        if (got < 36 || got > sizeof(buf)) return false;

        uint32_t magic;
        memcpy(&magic, buf, 4);
        if (magic != HEF_VAULT_MAGIC) return false;

        uint8_t  version = buf[4];
        if (version != HEF_VAULT_VERSION) {
            // Versao desconhecida: Nao tenta decifrar (impossivel garantir
            // integridade do layout). Mantem o vault intacto para inspecao.
            return false;
        }

        flags_     = buf[5];
        uint16_t totalLen;
        memcpy(&totalLen, buf + 6, 2);
        if ((size_t)totalLen + 36 != got) return false;   // integridade do tamanho

        const uint8_t* iv  = buf + 8;
        const uint8_t* tag = buf + 20;
        const uint8_t* ct  = buf + 36;

        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[2048];
        int ptLen = gcm.decrypt(ct, totalLen, plain, sizeof(plain),
                                0, 0, iv, HEF_IV_LEN);
        if (ptLen < 0) return false;

        // Parse TLV
        const uint8_t* v; size_t l;
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_PSK, &v, &l) && l == HEF_KEY_LEN) {
            memcpy(masterPsk_, v, l);
            havePsk_ = true;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_ENROLL, &v, &l)) {
            size_t n = l / sizeof(HefEnrollment);
            if (n > HEF_MAX_ENROLLMENTS) n = HEF_MAX_ENROLLMENTS;
            memcpy(enroll_, v, n * sizeof(HefEnrollment));
            enrollCount_ = (uint8_t)n;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_NODE_ID, &v, &l) && l == 2) {
            uint16_t stored;
            memcpy(&stored, v, 2);
            if (stored != 0) nodeId_ = stored;
        }
        return true;
    }

    bool save() {
        // Monta TLV
        uint8_t plain[2048];
        size_t pos = 0;

        if (havePsk_) {
            pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_PSK, masterPsk_, HEF_KEY_LEN);
        }
        if (enrollCount_ > 0) {
            pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_ENROLL,
                            (const uint8_t*)enroll_, enrollCount_ * sizeof(HefEnrollment));
        }
        uint8_t nid[2];
        nid[0] = (uint8_t)(nodeId_ & 0xFF);
        nid[1] = (uint8_t)(nodeId_ >> 8);
        pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_NODE_ID, nid, 2);

        // Cifra
        uint8_t iv[HEF_IV_LEN];
        esp_fill_random(iv, sizeof(iv));
        uint8_t cipher[2048];
        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        int ctLen = gcm.encrypt(plain, pos, cipher, sizeof(cipher), 0, 0, NULL, 0);
        if (ctLen < 0) return false;

        uint8_t out[2048];
        uint32_t magic = HEF_VAULT_MAGIC;
        memcpy(out, magic, 4);
        out[4] = HEF_VAULT_VERSION;
        out[5] = flags_;
        uint16_t tl = (uint16_t)ctLen;
        memcpy(out + 6, &tl, 2);
        memcpy(out + 8, iv, HEF_IV_LEN);
        memcpy(out + 20, cipher + ctLen - HEF_AEAD_TAG_LEN, HEF_AEAD_TAG_LEN);
        memcpy(out + 36, cipher, ctLen - HEF_AEAD_TAG_LEN);

        size_t total = 36 + (size_t)ctLen;
        prefs_.putBytes(HEF_NVS_KEY_VAULT, out, total);
        return true;
    }

    // ---- Segredos (com fallback seguro) ----

    bool getWifiPassword(char* out, size_t n) {
        if (!load()) { if (n) out[0] = 0; return false; }
        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        if (got < 36) return false;
        uint16_t totalLen; memcpy(&totalLen, buf + 6, 2);
        const uint8_t* iv = buf + 8; const uint8_t* tag = buf + 20; const uint8_t* ct = buf + 36;
        AeadGcm gcm; gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[2048];
        int ptLen = gcm.decrypt(ct, totalLen, plain, sizeof(plain), 0, 0, iv, HEF_IV_LEN);
        if (ptLen < 0) return false;
        const uint8_t* v; size_t l;
        if (!tlvFind(plain, (size_t)ptLen, HEF_TLV_WIFI_PASS, &v, &l)) return false;
        size_t cp = (l < n - 1) ? l : n - 1;
        memcpy(out, v, cp); out[cp] = 0;
        return true;
    }

    bool setWifiPassword(const char* pass) {
        if (!pass || strlen(pass) < 8) return false;
        return setSecret(HEF_TLV_WIFI_PASS, (const uint8_t*)pass, strlen(pass) + 1);
    }

    bool getCliUsername(char* out, size_t n) {
        if (!load()) { if (n) out[0] = 0; return false; }
        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        if (got < 36) return false;
        uint16_t totalLen; memcpy(&totalLen, buf + 6, 2);
        AeadGcm gcm; gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[2048];
        int ptLen = gcm.decrypt(buf + 36, totalLen, plain, sizeof(plain), 0, 0, buf + 8, HEF_IV_LEN);
        if (ptLen < 0) return false;
        const uint8_t* v; size_t l;
        if (!tlvFind(plain, (size_t)ptLen, HEF_TLV_CLI_USER, &v, &l)) return false;
        size_t cp = (l < n - 1) ? l : n - 1;
        memcpy(out, v, cp); out[cp] = 0;
        return true;
    }

    bool setCliUsername(const char* user) {
        if (!user || strlen(user) < 3) return false;
        return setSecret(HEF_TLV_CLI_USER, (const uint8_t*)user, strlen(user) + 1);
    }

    bool getCliPassword(char* out, size_t n) {
        if (!load()) { if (n) out[0] = 0; return false; }
        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        if (got < 36) return false;
        uint16_t totalLen; memcpy(&totalLen, buf + 6, 2);
        AeadGcm gcm; gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[2048];
        int ptLen = gcm.decrypt(buf + 36, totalLen, plain, sizeof(plain), 0, 0, buf + 8, HEF_IV_LEN);
        if (ptLen < 0) return false;
        const uint8_t* v; size_t l;
        if (!tlvFind(plain, (size_t)ptLen, HEF_TLV_CLI_PASS, &v, &l)) return false;
        size_t cp = (l < n - 1) ? l : n - 1;
        memcpy(out, v, cp); out[cp] = 0;
        return true;
    }

    bool setCliPassword(const char* pass) {
        if (!pass || strlen(pass) < 10) return false;
        return setSecret(HEF_TLV_CLI_PASS, (const uint8_t*)pass, strlen(pass) + 1);
    }

    bool getTotpSecret(uint8_t* out, size_t* outLen) {
        if (!load()) return false;
        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        if (got < 36) return false;
        uint16_t totalLen; memcpy(&totalLen, buf + 6, 2);
        AeadGcm gcm; gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[2048];
        int ptLen = gcm.decrypt(buf + 36, totalLen, plain, sizeof(plain), 0, 0, buf + 8, HEF_IV_LEN);
        if (ptLen < 0) return false;
        const uint8_t* v; size_t l;
        if (!tlvFind(plain, (size_t)ptLen, HEF_TLV_TOTP, &v, &l)) return false;
        if (l > *outLen) l = *outLen;
        memcpy(out, v, l); *outLen = l;
        return true;
    }

    bool setTotpSecret(const uint8_t* sec, size_t len) {
        return setSecret(HEF_TLV_TOTP, sec, len);
    }

    // Reescreve uma entrada TLV preservando as demais.
    bool setSecret(uint8_t type, const uint8_t* val, size_t len) {
        uint8_t buf[2048];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        uint8_t plain[2048];
        size_t plainLen = 0;

        if (got >= 36) {
            uint32_t magic; memcpy(&magic, buf, 4);
            uint16_t totalLen; memcpy(&totalLen, buf + 6, 2);
            if (magic == HEF_VAULT_MAGIC && (size_t)totalLen + 36 == got) {
                AeadGcm gcm; gcm.setKey(vaultKey_, sizeof(vaultKey_));
                int ptLen = gcm.decrypt(buf + 36, totalLen, plain, sizeof(plain), 0, 0, buf + 8, HEF_IV_LEN);
                if (ptLen > 0) plainLen = (size_t)ptLen;
            }
        }
        if (plainLen == 0) plainLen = 0;

        // Remove entrada existente e reconstroi o TLV.
        uint8_t rebuilt[2048];
        size_t pos = 0;
        size_t p = 0;
        while (p + 3 <= plainLen) {
            uint8_t  t = plain[p];
            uint16_t l = (uint16_t)plain[p + 1] | ((uint16_t)plain[p + 2] << 8);
            if (p + 3 + l > plainLen) break;
            if (t != type) {
                pos = tlvAppend(rebuilt, sizeof(rebuilt), pos, t, plain + p + 3, l);
            }
            p += 3 + l;
        }
        if (val && len) pos = tlvAppend(rebuilt, sizeof(rebuilt), pos, type, val, len);

        // Re-cifra preservando PSK/enroll/nodeId guardados em RAM.
        uint8_t iv[HEF_IV_LEN];
        esp_fill_random(iv, sizeof(iv));
        uint8_t cipher[2048];
        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        int ctLen = gcm.encrypt(rebuilt, pos, cipher, sizeof(cipher), 0, 0, NULL, 0);
        if (ctLen < 0) return false;

        uint8_t out[2048];
        uint32_t magic = HEF_VAULT_MAGIC;
        memcpy(out, magic, 4);
        out[4] = HEF_VAULT_VERSION;
        out[5] = flags_;
        uint16_t tl = (uint16_t)ctLen;
        memcpy(out + 6, &tl, 2);
        memcpy(out + 8, iv, HEF_IV_LEN);
        memcpy(out + 20, cipher + ctLen - HEF_AEAD_TAG_LEN, HEF_AEAD_TAG_LEN);
        memcpy(out + 36, cipher, ctLen - HEF_AEAD_TAG_LEN);

        prefs_.putBytes(HEF_NVS_KEY_VAULT, out, 36 + (size_t)ctLen);
        return true;
    }

    // ---- PSK de deploy / enrollments ----

    bool setDeploymentPsk(const uint8_t* psk, size_t len) {
        if (!psk || len != HEF_KEY_LEN) return false;
        memcpy(masterPsk_, psk, len);
        havePsk_ = true;
        return save();
    }

    bool hasPsk() const { return havePsk_; }

    const uint8_t* getPsk() const { return havePsk_ ? masterPsk_ : nullptr; }

    bool enrollNode(uint16_t nodeId, uint8_t keyId) {
        if (nodeId == 0) return false;
        for (uint8_t i = 0; i < enrollCount_; i++) {
            if (enroll_[i].nodeId == nodeId) { enroll_[i].keyId = keyId; return save(); }
        }
        if (enrollCount_ >= HEF_MAX_ENROLLMENTS) return false;
        enroll_[enrollCount_].nodeId = nodeId;
        enroll_[enrollCount_].keyId  = keyId;
        enrollCount_++;
        return save();
    }

    bool isEnrolled(uint16_t nodeId, uint8_t* keyIdOut) const {
        for (uint8_t i = 0; i < enrollCount_; i++) {
            if (enroll_[i].nodeId == nodeId) {
                if (keyIdOut) *keyIdOut = enroll_[i].keyId;
                return true;
            }
        }
        return false;
    }

    uint8_t enrollmentCount() const { return enrollCount_; }

    // ---- Flags / estado ----

    bool isProvisioned() const { return (flags_ & HEF_FLAG_PROVISIONED) != 0; }
    void setProvisioned(bool v) {
        if (v) flags_ |= HEF_FLAG_PROVISIONED; else flags_ &= (uint8_t)~HEF_FLAG_PROVISIONED;
    }

    bool isDebugEnabled() const { return (flags_ & HEF_FLAG_DEBUG) != 0; }
    void setDebugEnabled(bool v) {
        if (v) flags_ |= HEF_FLAG_DEBUG; else flags_ &= (uint8_t)~HEF_FLAG_DEBUG;
    }

    uint16_t nodeId() const { return nodeId_; }

    // ---- Manutencao ----

    bool factoryReset() {
        prefs_.remove(HEF_NVS_KEY_VAULT);
        wipePsk();
        enrollCount_ = 0;
        flags_ = 0;
        memset(enroll_, 0, sizeof(enroll_));
        prefs_.putBytes(HEF_NVS_KEY_VAULT, (const uint8_t*)HEF_VAULT_MAGIC, 0); // placeholder
        prefs_.remove(HEF_NVS_KEY_VAULT);
        return true;
    }
};

#endif // HEF_CONFIG_H
