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
//   | totalLen u16 LE           |  ciphertext + tag GCM
//   | iv       u8[12]           |
//   | reservado u8[16]          |  (zero; semantica futura)
//   +---------------------------+
//   | ciphertext || tag (16)    |  AES-256-GCM
//   +---------------------------+
//
// totalLen cobre ciphertext E tag: a integridade do blob e' verificada
// por (36 + totalLen == tamanho gravado).
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
#include "peer_state.h"

#define HEF_TLV_WIFI_PASS 0x01
#define HEF_TLV_CLI_USER  0x02
#define HEF_TLV_CLI_PASS  0x03
#define HEF_TLV_TOTP      0x04
#define HEF_TLV_PSK       0x05
#define HEF_TLV_ENROLL    0x06
#define HEF_TLV_NODE_ID   0x07
#define HEF_TLV_TZ_MIN    0x08
#define HEF_TLV_WIFI_SSID 0x09
#define HEF_TLV_PEER_STATE 0x0A   // estado anti-replay por par (epoch + high-water)

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
    // Estado anti-replay persistido por par (epoch + high-water).
    // Sem isso, um frame capturado antes de um reinicio do receptor seria
    // aceito como frame novo (o par comecaria sem epoch/contador).
    PeerStateStore peerStates_;
    bool loaded_;

    // Cache dos segredos em RAM (decifrados uma vez no boot).
    char    wifiSsid_[33];
    char    wifiPass_[33];
    char    cliUser_[17];
    char    cliPass_[33];
    uint8_t totpSecret_[HEF_TOTP_SECRET_MAX];
    size_t  totpLen_;
    bool    secretsLoaded_;

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
        : havePsk_(false), flags_(0), nodeId_(0), enrollCount_(0), loaded_(false),
          totpLen_(0), secretsLoaded_(false) {
        memset(masterPsk_, 0, sizeof(masterPsk_));
        memset(enroll_, 0, sizeof(enroll_));
        memset(wifiSsid_, 0, sizeof(wifiSsid_));
        memset(wifiPass_, 0, sizeof(wifiPass_));
        memset(cliUser_, 0, sizeof(cliUser_));
        memset(cliPass_, 0, sizeof(cliPass_));
        memset(totpSecret_, 0, sizeof(totpSecret_));
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
        volatile uint8_t* p;
        p = (volatile uint8_t*)wifiPass_; for (size_t i = 0; i < sizeof(wifiPass_); i++) p[i] = 0;
        p = (volatile uint8_t*)cliPass_;  for (size_t i = 0; i < sizeof(cliPass_); i++) p[i] = 0;
        p = (volatile uint8_t*)totpSecret_; for (size_t i = 0; i < sizeof(totpSecret_); i++) p[i] = 0;
        totpLen_ = 0;
        prefs_.end();
        loaded_ = false;
        secretsLoaded_ = false;
    }

    bool isLoaded() const { return loaded_; }

    // ---- Persistencia ----

    bool load() {
        havePsk_ = false;
        enrollCount_ = 0;
        flags_ = 0;
        peerStates_.clear();

        size_t blobLen = prefs_.getBytesLength(HEF_NVS_KEY_VAULT);
        if (blobLen < 52) return false;   // header 36 + tag GCM 16 (payload vazio)
        if (blobLen > HEF_VAULT_BUF) return false;

        uint8_t buf[HEF_VAULT_BUF];
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

        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        uint8_t plain[HEF_VAULT_BUF];
        int ptLen = gcm.decrypt(buf + 36, totalLen, plain, sizeof(plain),
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
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_PEER_STATE, &v, &l)) {
            peerStates_.deserialize(v, l);
        }

        // Cache dos segredos em RAM
        wifiSsid_[0] = wifiPass_[0] = cliUser_[0] = cliPass_[0] = 0;
        totpLen_ = 0;
        secretsLoaded_ = true;
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_WIFI_SSID, &v, &l)) {
            size_t cp = (l < sizeof(wifiSsid_) - 1) ? l : sizeof(wifiSsid_) - 1;
            memcpy(wifiSsid_, v, cp); wifiSsid_[cp] = 0;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_WIFI_PASS, &v, &l)) {
            size_t cp = (l < sizeof(wifiPass_) - 1) ? l : sizeof(wifiPass_) - 1;
            memcpy(wifiPass_, v, cp); wifiPass_[cp] = 0;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_CLI_USER, &v, &l)) {
            size_t cp = (l < sizeof(cliUser_) - 1) ? l : sizeof(cliUser_) - 1;
            memcpy(cliUser_, v, cp); cliUser_[cp] = 0;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_CLI_PASS, &v, &l)) {
            size_t cp = (l < sizeof(cliPass_) - 1) ? l : sizeof(cliPass_) - 1;
            memcpy(cliPass_, v, cp); cliPass_[cp] = 0;
        }
        if (tlvFind(plain, (size_t)ptLen, HEF_TLV_TOTP, &v, &l) && l <= HEF_TOTP_SECRET_MAX) {
            memcpy(totpSecret_, v, l); totpLen_ = l;
        }
        return true;
    }

    bool save() {
        // Monta TLV.
        //
        // IMPORTANTE: o tamanho e' calculado ANTES de escrever. O
        // tlvAppend() historicamente devolvia o mesmo `pos` quando o
        // espaco faltava, o que descartaria a entrada SILENCIOSAMENTE.
        // Para o estado anti-replay isso seria uma falha de seguranca
        // (o par perderia o epoch persistido e o replay pos-reboot
        // voltaria a ser aceito). Agora o vault falha FECHADO.
        uint8_t plain[HEF_VAULT_BUF];
        size_t pos = 0;

        size_t need = 0;
        if (havePsk_)                      need += 3 + HEF_KEY_LEN;
        if (enrollCount_ > 0)              need += 3 + (size_t)enrollCount_ * sizeof(HefEnrollment);
        need += 3 + 2;                                       // node_id
        if (wifiSsid_[0])                  need += 3 + strlen(wifiSsid_) + 1;
        if (wifiPass_[0])                  need += 3 + strlen(wifiPass_) + 1;
        if (cliUser_[0])                   need += 3 + strlen(cliUser_) + 1;
        if (cliPass_[0])                   need += 3 + strlen(cliPass_) + 1;
        if (totpLen_ > 0)                  need += 3 + totpLen_;
        size_t peerLen = peerStates_.serializedSize();
        if (peerLen > 0)                   need += 3 + peerLen;
        // O blob final e' header (36) + ciphertext + tag GCM (16).
        // Precisa caber em HEF_VAULT_BUF: sem espaco, falha FECHADA
        // (descartar a entrada em silencio seria uma falha de seguranca).
        if (need > HEF_VAULT_MAX_PLAIN) return false;

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

        // Segredos em cache: precisam ser reescritos aqui, senao um save()
        // disparado por enrollNode()/setDeploymentPsk() APAGARIA as
        // credenciais ja provisionadas.
        if (wifiSsid_[0]) pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_WIFI_SSID,
                                          (const uint8_t*)wifiSsid_, strlen(wifiSsid_) + 1);
        if (wifiPass_[0]) pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_WIFI_PASS,
                                          (const uint8_t*)wifiPass_, strlen(wifiPass_) + 1);
        if (cliUser_[0])  pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_CLI_USER,
                                          (const uint8_t*)cliUser_, strlen(cliUser_) + 1);
        if (cliPass_[0])  pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_CLI_PASS,
                                          (const uint8_t*)cliPass_, strlen(cliPass_) + 1);
        if (totpLen_ > 0) pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_TOTP,
                                          totpSecret_, totpLen_);

        // Estado anti-replay por par.
        if (peerLen > 0) {
            uint8_t pbuf[HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN];
            size_t wrote = peerStates_.serialize(pbuf, sizeof(pbuf));
            if (wrote != peerLen) return false;   // falha fechada
            pos = tlvAppend(plain, sizeof(plain), pos, HEF_TLV_PEER_STATE, pbuf, peerLen);
        }

        // Cifra
        uint8_t iv[HEF_IV_LEN];
        esp_fill_random(iv, sizeof(iv));
        uint8_t cipher[HEF_VAULT_BUF];
        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        if (pos != need) return false;   // inconsistencia: falha fechada
        int ctLen = gcm.encrypt(plain, pos, cipher, sizeof(cipher), 0, 0, NULL, 0);
        if (ctLen < 0) return false;
        if (36 + (size_t)ctLen > HEF_VAULT_BUF) return false;   // falha fechada

        uint8_t out[HEF_VAULT_BUF];
        uint32_t magic = HEF_VAULT_MAGIC;
        memcpy(out, &magic, 4);
        out[4] = HEF_VAULT_VERSION;
        out[5] = flags_;
        uint16_t tl = (uint16_t)ctLen;
        memcpy(out + 6, &tl, 2);
        memcpy(out + 8, iv, HEF_IV_LEN);
        memset(out + 20, 0, 16);            // reservado (semantica futura)
        // ciphertext || tag GCM, contiguos.
        memcpy(out + 36, cipher, (size_t)ctLen);

        size_t total = 36 + (size_t)ctLen;
        if (prefs_.putBytes(HEF_NVS_KEY_VAULT, out, total) == 0) {
            return false;   // NVS recusou a escrita (sem flash livre?)
        }
        return true;
    }

    // ---- Segredos (com fallback seguro) ----

    bool getWifiPassword(char* out, size_t n) {
        if (!out || n == 0) return false;
        if (!secretsLoaded_) load();
        if (!wifiPass_[0]) return false;
        strncpy(out, wifiPass_, n - 1);
        out[n - 1] = 0;
        return true;
    }

    bool getWifiSsid(char* out, size_t n) {
        if (!out || n == 0) return false;
        if (!secretsLoaded_) load();
        if (!wifiSsid_[0]) return false;
        strncpy(out, wifiSsid_, n - 1);
        out[n - 1] = 0;
        return true;
    }

    bool setWifiSsid(const char* ssid) {
        if (!ssid || strlen(ssid) < 1 || strlen(ssid) > 32) return false;
        return setSecret(HEF_TLV_WIFI_SSID, (const uint8_t*)ssid, strlen(ssid) + 1);
    }

    bool setWifiPassword(const char* pass) {
        if (!pass || strlen(pass) < 8) return false;
        return setSecret(HEF_TLV_WIFI_PASS, (const uint8_t*)pass, strlen(pass) + 1);
    }

    bool getCliUsername(char* out, size_t n) {
        if (!out || n == 0) return false;
        if (!secretsLoaded_) load();
        if (!cliUser_[0]) return false;
        strncpy(out, cliUser_, n - 1);
        out[n - 1] = 0;
        return true;
    }

    bool setCliUsername(const char* user) {
        if (!user || strlen(user) < 3) return false;
        return setSecret(HEF_TLV_CLI_USER, (const uint8_t*)user, strlen(user) + 1);
    }

    bool getCliPassword(char* out, size_t n) {
        if (!out || n == 0) return false;
        if (!secretsLoaded_) load();
        if (!cliPass_[0]) return false;
        strncpy(out, cliPass_, n - 1);
        out[n - 1] = 0;
        return true;
    }

    bool setCliPassword(const char* pass) {
        if (!pass || strlen(pass) < 10) return false;
        return setSecret(HEF_TLV_CLI_PASS, (const uint8_t*)pass, strlen(pass) + 1);
    }

    bool getTotpSecret(uint8_t* out, size_t* outLen) {
        if (!out || !outLen) return false;
        if (!secretsLoaded_) load();
        if (totpLen_ == 0) return false;
        if (totpLen_ > *outLen) return false;
        memcpy(out, totpSecret_, totpLen_);
        *outLen = totpLen_;
        return true;
    }

    bool setTotpSecret(const uint8_t* sec, size_t len) {
        return setSecret(HEF_TLV_TOTP, sec, len);
    }

    // Reescreve uma entrada TLV preservando as demais.
    bool setSecret(uint8_t type, const uint8_t* val, size_t len) {
        uint8_t buf[HEF_VAULT_BUF];
        size_t got = prefs_.getBytes(HEF_NVS_KEY_VAULT, buf, sizeof(buf));
        uint8_t plain[HEF_VAULT_BUF];
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
        //
        // O estado anti-replay (HEF_TLV_PEER_STATE) e' SEMPRE reescrito a
        // partir do espelho em RAM, nunca do plaintext gravado: o flush
        // periodico pode nao ter ocorrido ainda e o plaintext pode estar
        // mais velho que o estado real dos pares.
        uint8_t rebuilt[HEF_VAULT_BUF];
        size_t pos = 0;
        size_t p = 0;
        while (p + 3 <= plainLen) {
            uint8_t  t = plain[p];
            uint16_t l = (uint16_t)plain[p + 1] | ((uint16_t)plain[p + 2] << 8);
            if (p + 3 + l > plainLen) break;
            if (t != type && t != HEF_TLV_PEER_STATE) {
                size_t before = pos;
                pos = tlvAppend(rebuilt, sizeof(rebuilt), pos, t, plain + p + 3, l);
                if (pos != before + 3 + (size_t)l) return false;  // sem espaco
            }
            p += 3 + l;
        }
        if (val && len) {
            size_t before = pos;
            pos = tlvAppend(rebuilt, sizeof(rebuilt), pos, type, val, len);
            if (pos != before + 3 + len) return false;   // sem espaco
        }
        size_t peerLen = peerStates_.serializedSize();
        if (peerLen > 0) {
            uint8_t pbuf[HEF_MAX_ENROLLMENTS * HEF_PEER_STATE_REC_LEN];
            size_t wrote = peerStates_.serialize(pbuf, sizeof(pbuf));
            if (wrote != peerLen) return false;
            size_t before = pos;
            pos = tlvAppend(rebuilt, sizeof(rebuilt), pos, HEF_TLV_PEER_STATE, pbuf, peerLen);
            if (pos != before + 3 + peerLen) return false;   // sem espaco
        }
        // O blob final e' header (36) + ciphertext + tag GCM (16).
        if (pos > HEF_VAULT_MAX_PLAIN) return false;   // falha fechada

        // Re-cifra preservando PSK/enroll/nodeId guardados em RAM.
        uint8_t iv[HEF_IV_LEN];
        esp_fill_random(iv, sizeof(iv));
        uint8_t cipher[HEF_VAULT_BUF];
        AeadGcm gcm;
        gcm.setKey(vaultKey_, sizeof(vaultKey_));
        int ctLen = gcm.encrypt(rebuilt, pos, cipher, sizeof(cipher), 0, 0, NULL, 0);
        if (ctLen < 0) return false;
        if (36 + (size_t)ctLen > HEF_VAULT_BUF) return false;   // falha fechada

        uint8_t out[HEF_VAULT_BUF];
        uint32_t magic = HEF_VAULT_MAGIC;
        memcpy(out, &magic, 4);
        out[4] = HEF_VAULT_VERSION;
        out[5] = flags_;
        uint16_t tl = (uint16_t)ctLen;
        memcpy(out + 6, &tl, 2);
        memcpy(out + 8, iv, HEF_IV_LEN);
        memset(out + 20, 0, 16);
        memcpy(out + 36, cipher, (size_t)ctLen);

        if (prefs_.putBytes(HEF_NVS_KEY_VAULT, out, 36 + (size_t)ctLen) == 0) {
            return false;
        }
        // Recarrega o cache IMEDIATAMENTE. Sem isso, um save() posterior
        // (enrollNode/setDeploymentPsk) gravaria os campos de cache vazios
        // e apagaria as credenciais recem-gravadas.
        // O estado anti-replay e' preservado: ele foi gravado no blob acima
        // a partir do espelho em RAM, que e' a versao mais recente.
        load();
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

    // Enumera os pares enrolled (necessario para reidratar o estado
    // anti-replay no boot do receptor).
    bool getEnrollment(uint8_t index, uint16_t* nodeIdOut, uint8_t* keyIdOut) const {
        if (index >= enrollCount_) return false;
        if (nodeIdOut) *nodeIdOut = enroll_[index].nodeId;
        if (keyIdOut)  *keyIdOut  = enroll_[index].keyId;
        return true;
    }

    // Lookup inverso: keyId (campo do cabecalho do frame) -> node_id.
    // O receptor precisa do node_id ANTES de decifrar, para derivar a chave.
    bool nodeIdForKeyId(uint8_t keyId, uint16_t* out) const {
        for (uint8_t i = 0; i < enrollCount_; i++) {
            if (enroll_[i].keyId == keyId) {
                if (out) *out = enroll_[i].nodeId;
                return true;
            }
        }
        return false;
    }

    uint8_t enrollmentCount() const { return enrollCount_; }

    // ---- Estado anti-replay por par (persistido no vault cifrado) ----
    //
    // get/put mexem apenas na RAM (espelho). A gravacao efetiva na flash
    // acontece em save(), que o Node2 chama quando o epoch muda (urgente)
    // ou periodicamente (HEF_PEER_STATE_FLUSH_MS).

    bool getPeerState(uint16_t nodeId, uint16_t* epoch, uint32_t* counter) const {
        return peerStates_.get(nodeId, epoch, counter);
    }

    bool putPeerState(uint16_t nodeId, uint16_t epoch, uint32_t counter) {
        return peerStates_.put(nodeId, epoch, counter);
    }

    uint8_t peerStateCount() const { return peerStates_.count(); }

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

    // Apaga TODO o conteudo do vault (PSK, enrollments, credenciais,
    // segredo TOTP). A chave do vault e' derivada do MAC do efuse; um
    // factory reset nao a expoe nem a altera.
    bool factoryReset() {
        prefs_.remove(HEF_NVS_KEY_VAULT);
        wipePsk();
        enrollCount_ = 0;
        flags_ = 0;
        memset(enroll_, 0, sizeof(enroll_));
        // O estado anti-replay tambem e' apagado: um vault novo com pares
        // novos nao pode herdar epoch/contador de pares antigos.
        peerStates_.clear();
        memset(wifiSsid_, 0, sizeof(wifiSsid_));
        memset(wifiPass_, 0, sizeof(wifiPass_));
        memset(cliUser_, 0, sizeof(cliUser_));
        memset(cliPass_, 0, sizeof(cliPass_));
        memset(totpSecret_, 0, sizeof(totpSecret_));
        totpLen_ = 0;
        secretsLoaded_ = true;
        return true;
    }
};

#endif // HEF_CONFIG_H
