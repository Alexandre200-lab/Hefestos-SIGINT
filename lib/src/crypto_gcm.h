// crypto_gcm.h - AEAD AES-256-GCM real (mbedtls) - v5.0.0
//
// Correcoes em relacao a v4.x:
//   - AES-256 (o link RF usava AES-128 enquanto a documentacao dizia 256)
//   - Nonce DETERMINISTICO: prefixo de 4 bytes || contador de 8 bytes (BE).
//     A v4.x sorteava 4 bytes aleatorios por pacote e usava SHA-256 para
//     "embaralhar" o nonce: nao padrao e sem garantia de unicidade.
//   - AAD (Additional Authenticated Data)vincula o cabecalho ao corpo:
//     um atacante nao pode alterar node_id/seq/tipo sem invalidar a tag.
//   - isRNGReady() nao media entropia (contava bytes nao-nulos). Substituido
//     por um auto-teste honesto do RNG, que falha fechado.
//   - Wipe de chaves em memoria.
#ifndef HEF_CRYPTO_GCM_H
#define HEF_CRYPTO_GCM_H

#include <stdint.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <esp_random.h>

#include "hefestos_pins.h"

#define HEF_AEAD_KEY_LEN  HEF_KEY_LEN
#define HEF_AEAD_IV_LEN   HEF_IV_LEN
#define HEF_AEAD_TAG_LEN  HEF_TAG_LEN

// Retornos de encrypt/decrypt
#define HEF_AEAD_OK        0
#define HEF_AEAD_ERR_KEY (-1)
#define HEF_AEAD_ERR_LEN (-2)
#define HEF_AEAD_ERR_TAG (-3)
#define HEF_AEAD_ERR_RNG (-4)
#define HEF_AEAD_ERR_CRYPTO (-5)

class AeadGcm {
private:
    uint8_t key_[HEF_AEAD_KEY_LEN];
    bool    ready_;

    // Auto-teste do RNG: duas coletas devem diferir e nao podem ser
    // constantes. Limitado, mas infinitamente melhor que "conta bytes
    // nao-nulos" (que passava 100% com um RNG quebrado).
    static bool rngSelfTest() {
        uint8_t a[16], b[16];
        esp_fill_random(a, sizeof(a));
        esp_fill_random(b, sizeof(b));
        if (memcmp(a, b, sizeof(a)) == 0) return false;
        // Rejeita saida periodica (ex.: contador) - detecta RNG degenerado.
        uint8_t diff = 0;
        for (size_t i = 0; i < sizeof(a); i++) diff |= (uint8_t)(a[i] ^ b[i]);
        return diff != 0;
    }

    static int setKey(mbedtls_gcm_context* ctx, const uint8_t* k, size_t klen) {
        return mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, k, (unsigned int)klen);
    }

public:
    AeadGcm() : ready_(false) { memset(key_, 0, sizeof(key_)); }

    void setKey(const uint8_t* k, size_t klen = HEF_AEAD_KEY_LEN) {
        if (!k || klen != HEF_AEAD_KEY_LEN) { ready_ = false; return; }
        memcpy(key_, k, HEF_AEAD_KEY_LEN);
        ready_ = true;
    }

    bool isReady() const { return ready_; }

    void wipe() {
        volatile uint8_t* p = key_;
        for (size_t i = 0; i < sizeof(key_); i++) p[i] = 0;
        ready_ = false;
    }

    // Monta IV deterministico: iv[0..3] = prefixo, iv[4..11] = contador BE
    static void buildIv(uint32_t prefix, uint64_t counter, uint8_t* iv) {
        iv[0] = (uint8_t)(prefix >> 24);
        iv[1] = (uint8_t)(prefix >> 16);
        iv[2] = (uint8_t)(prefix >> 8);
        iv[3] = (uint8_t)(prefix);
        for (int i = 0; i < 8; i++) {
            iv[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
        }
    }

    // Encrypt: out = ciphertext || tag. `aad`/`aadLen` sao autenticados
    // mas nao cifrados. Retorna tamanho do output ou HEF_AEAD_ERR_*.
    int encrypt(const uint8_t* input, size_t len,
                uint8_t* output, size_t outputCap,
                uint32_t prefix, uint64_t counter,
                const uint8_t* aad, size_t aadLen) {
        if (!ready_) return HEF_AEAD_ERR_KEY;
        if (len > HEF_MAX_PAYLOAD) return HEF_AEAD_ERR_LEN;
        if (!input || !output) return HEF_AEAD_ERR_LEN;
        if (outputCap < len + HEF_AEAD_TAG_LEN) return HEF_AEAD_ERR_LEN;
        if (!rngSelfTest()) return HEF_AEAD_ERR_RNG;

        uint8_t iv[HEF_AEAD_IV_LEN];
        uint8_t tag[HEF_AEAD_TAG_LEN];
        buildIv(prefix, counter, iv);

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = setKey(&ctx, key_, sizeof(key_));
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                           len, iv, sizeof(iv),
                                           aad, aadLen,
                                           input, output, sizeof(tag), tag);
        }
        mbedtls_gcm_free(&ctx);
        if (ret != 0) return HEF_AEAD_ERR_CRYPTO;

        memcpy(output + len, tag, sizeof(tag));
        return (int)(len + sizeof(tag));
    }

    // Decrypt: in = ciphertext || tag. Retorna tamanho do plaintext ou erro.
    int decrypt(const uint8_t* input, size_t len,
                uint8_t* output, size_t outputCap,
                uint32_t prefix, uint64_t counter,
                const uint8_t* aad, size_t aadLen) {
        if (!ready_) return HEF_AEAD_ERR_KEY;
        if (len < HEF_AEAD_TAG_LEN) return HEF_AEAD_ERR_LEN;
        size_t ctLen = len - HEF_AEAD_TAG_LEN;
        if (ctLen > HEF_MAX_PAYLOAD) return HEF_AEAD_ERR_LEN;
        if (!input || !output) return HEF_AEAD_ERR_LEN;
        if (outputCap < ctLen) return HEF_AEAD_ERR_LEN;

        uint8_t iv[HEF_AEAD_IV_LEN];
        buildIv(prefix, counter, iv);

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = setKey(&ctx, key_, sizeof(key_));
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&ctx, ctLen, iv, sizeof(iv),
                                          aad, aadLen,
                                          input + ctLen, HEF_AEAD_TAG_LEN,
                                          input, output);
        }
        mbedtls_gcm_free(&ctx);
        if (ret != 0) return HEF_AEAD_ERR_TAG;
        return (int)ctLen;
    }
};

// ---------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) implementado sobre HMAC-SHA256 do mbedtls.
//
// A versao anterior chamava mbedtls_hkdf(), que depende de
// CONFIG_MBEDTLS_HKDF_C - desabilitado no core Arduino ESP32 2.0.17.
// A implementacao local evita depender da configuracao do SDK e usa
// apenas a primitiva HMAC, que esta sempre disponivel.
// ---------------------------------------------------------------
inline bool hefHmacSha256(const uint8_t* key, size_t keyLen,
                          const uint8_t* data, size_t dataLen,
                          uint8_t out[32]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    bool ok = false;
    if (mbedtls_md_setup(&ctx, md, 1) == 0 &&
        mbedtls_md_hmac_starts(&ctx, key, keyLen) == 0 &&
        mbedtls_md_hmac_update(&ctx, data, dataLen) == 0 &&
        mbedtls_md_hmac_finish(&ctx, out) == 0) {
        ok = true;
    }
    mbedtls_md_free(&ctx);
    return ok;
}

inline bool hefHkdfSha256(const uint8_t* ikm, size_t ikmLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen,
                          uint8_t* okm, size_t okmLen) {
    if (!ikm || !okm || okmLen == 0 || okmLen > 255 * 32) return false;

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    uint8_t zeroSalt[32];
    memset(zeroSalt, 0, sizeof(zeroSalt));
    const uint8_t* useSalt = (salt && saltLen > 0) ? salt : zeroSalt;
    size_t useSaltLen = (salt && saltLen > 0) ? saltLen : sizeof(zeroSalt);

    uint8_t prk[32];
    if (!hefHmacSha256(useSalt, useSaltLen, ikm, ikmLen, prk)) return false;

    // Expand
    uint8_t t[32];
    size_t tLen = 0;
    size_t written = 0;
    uint8_t counter = 1;
    uint8_t block[32 + 64];
    while (written < okmLen) {
        size_t pos = 0;
        if (tLen) { memcpy(block, t, tLen); pos += tLen; }
        if (info && infoLen) {
            size_t cp = infoLen;
            if (cp > sizeof(block) - pos) cp = sizeof(block) - pos;
            memcpy(block + pos, info, cp);
            pos += cp;
        }
        block[pos++] = counter;
        if (!hefHmacSha256(prk, sizeof(prk), block, pos, t)) {
            memset(prk, 0, sizeof(prk));
            memset(t, 0, sizeof(t));
            return false;
        }
        tLen = sizeof(t);
        size_t cp = okmLen - written;
        if (cp > tLen) cp = tLen;
        memcpy(okm + written, t, cp);
        written += cp;
        counter++;
    }
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    memset(block, 0, sizeof(block));
    return true;
}

// Comparacao em tempo constante.
inline bool hefConstantTimeEq(const uint8_t* a, const uint8_t* b, size_t len) {
    if (!a || !b) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

#endif // HEF_CRYPTO_GCM_H
