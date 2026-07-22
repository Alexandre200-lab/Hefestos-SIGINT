#ifndef CRYPTO_GCM_H
#define CRYPTO_GCM_H

#include <stdint.h>
#include <string.h>
#include <esp_timer.h>
#include <esp_random.h>
#include <mbedtls/gcm.h>

#define GCM_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define GCM_PAYLOAD_MAX 240

class AESGCM {
private:
    unsigned char key[GCM_KEY_SIZE];

public:
    AESGCM() {
        memset(key, 0, GCM_KEY_SIZE);
    }

    void setKey(const unsigned char* k, int len = GCM_KEY_SIZE) {
        if (len > GCM_KEY_SIZE) len = GCM_KEY_SIZE;
        memcpy(key, k, len);
    }

    int encrypt(const unsigned char* input, int len, unsigned char* output, uint32_t counter) {
        if (len > GCM_PAYLOAD_MAX) return -1;

        unsigned char iv[GCM_IV_SIZE];
        memcpy(iv, &counter, 4);
        esp_fill_random(iv + 4, 8);

        unsigned char tag[GCM_TAG_SIZE];
        size_t olen = 0;

        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret != 0) {
            mbedtls_gcm_free(&ctx);
            return -1;
        }

        ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
            len, iv, GCM_IV_SIZE, NULL, 0,
            input, output + GCM_IV_SIZE, GCM_TAG_SIZE, tag);
        mbedtls_gcm_free(&ctx);

        if (ret != 0) return -1;

        memcpy(output, iv, GCM_IV_SIZE);
        memcpy(output + GCM_IV_SIZE + len, tag, GCM_TAG_SIZE);

        return GCM_IV_SIZE + len + GCM_TAG_SIZE;
    }

    int decrypt(const unsigned char* input, int len, unsigned char* output) {
        if (len < GCM_IV_SIZE + GCM_TAG_SIZE) return -1;

        int ct_len = len - GCM_IV_SIZE - GCM_TAG_SIZE;
        if (ct_len > GCM_PAYLOAD_MAX) return -1;

        unsigned char iv[GCM_IV_SIZE];
        memcpy(iv, input, GCM_IV_SIZE);

        unsigned char tag[GCM_TAG_SIZE];
        memcpy(tag, input + GCM_IV_SIZE + ct_len, GCM_TAG_SIZE);

        size_t olen = 0;
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret != 0) {
            mbedtls_gcm_free(&ctx);
            return -1;
        }

        ret = mbedtls_gcm_auth_decrypt(&ctx, ct_len,
            iv, GCM_IV_SIZE, NULL, 0,
            tag, GCM_TAG_SIZE, input + GCM_IV_SIZE, output);
        mbedtls_gcm_free(&ctx);

        if (ret != 0) return -1;

        return ct_len;
    }
};

#endif
