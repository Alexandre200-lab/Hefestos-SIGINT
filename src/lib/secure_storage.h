#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include <stdint.h>
#include <string.h>
#include <esp_timer.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#define SECURE_STORAGE_KEY_SIZE 32
#define SECURE_STORAGE_IV_SIZE 12
#define SECURE_STORAGE_TAG_SIZE 16
#define SECURE_STORAGE_BLOCK 16

class SecureStorage {
private:
    unsigned char master_key[SECURE_STORAGE_KEY_SIZE];
    bool initialized;

    void deriveKey(const char* password, unsigned char* output) {
        const unsigned char salt[] = "Hefestos-Storage-v3";
        mbedtls_md_context_t md_ctx;
        mbedtls_md_init(&md_ctx);
        mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
        mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
            (const unsigned char*)password, strlen(password),
            salt, sizeof(salt),
            100000,
            SECURE_STORAGE_KEY_SIZE, output);
        mbedtls_md_free(&md_ctx);
    }

public:
    SecureStorage() : initialized(false) {}

    bool begin(const char* password) {
        if (!password || strlen(password) < 8) return false;
        deriveKey(password, master_key);
        initialized = true;
        return true;
    }

    bool beginRaw(const unsigned char* key) {
        if (!key) return false;
        memcpy(master_key, key, SECURE_STORAGE_KEY_SIZE);
        initialized = true;
        return true;
    }

    int encrypt(const unsigned char* input, int len, uint8_t* output, const unsigned char* iv) {
        if (!initialized) return -1;
        unsigned char tag[SECURE_STORAGE_TAG_SIZE];
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, master_key, 256);
        if (ret != 0) { mbedtls_gcm_free(&ctx); return -1; }
        ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
            len, iv, SECURE_STORAGE_IV_SIZE, NULL, 0,
            input, output, SECURE_STORAGE_TAG_SIZE, tag);
        mbedtls_gcm_free(&ctx);
        if (ret != 0) return -1;
        memcpy(output + len, tag, SECURE_STORAGE_TAG_SIZE);
        return len + SECURE_STORAGE_TAG_SIZE;
    }

    int decrypt(const unsigned char* input, int len, uint8_t* output, const unsigned char* iv) {
        if (!initialized) return -1;
        int ct_len = len - SECURE_STORAGE_TAG_SIZE;
        if (ct_len < 0) return -1;
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, master_key, 256);
        if (ret != 0) { mbedtls_gcm_free(&ctx); return -1; }
        ret = mbedtls_gcm_auth_decrypt(&ctx, ct_len,
            iv, SECURE_STORAGE_IV_SIZE, NULL, 0,
            input + ct_len, SECURE_STORAGE_TAG_SIZE, input, output);
        mbedtls_gcm_free(&ctx);
        return (ret == 0) ? ct_len : -1;
    }

    bool isInitialized() { return initialized; }
};

class SecureMem {
public:
    static void wipe(unsigned char* data, int len) {
        if (!data) return;
        for (int i = 0; i < len; i++) {
            data[i] = 0;
        }
    }

    static void wipeString(char* str) {
        if (!str) return;
        int len = strlen(str);
        for (int i = 0; i < len; i++) {
            str[i] = 0;
        }
    }
};

#endif
