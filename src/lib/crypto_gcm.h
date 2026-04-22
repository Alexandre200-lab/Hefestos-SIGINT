// crypto_gcm.h - AES-CTR + HMAC-SHA256
// Alternativa compatvel para AES-GCM no ESP32 IDF 3.3.x

#ifndef CRYPTO_GCM_H
#define CRYPTO_GCM_H

#include <stdint.h>
#include <string.h>
#include <esp_timer.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>

#define GCM_KEY_SIZE 16
#define GCM_IV_SIZE 16
#define GCM_TAG_SIZE 16
#define GCM_TAG_COMPACT 8
#define GCM_PAYLOAD_MAX 240

class AESGCM {
private:
    unsigned char key[GCM_KEY_SIZE];
    unsigned char hmac_key[32];

    void computeHmac(const unsigned char* key, const unsigned char* input, size_t len, unsigned char* output) {
        mbedtls_md_context_t ctx;
        mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
        
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
        mbedtls_md_hmac_starts(&ctx, key, 32);
        mbedtls_md_hmac_update(&ctx, input, len);
        mbedtls_md_hmac_finish(&ctx, output);
        mbedtls_md_free(&ctx);
    }

public:
    AESGCM() {
        memset(key, 0, GCM_KEY_SIZE);
        memset(hmac_key, 0, 32);
    }

    void setKey(const unsigned char* k, int len = GCM_KEY_SIZE) {
        if (len == GCM_KEY_SIZE) {
            memcpy(key, k, GCM_KEY_SIZE);
            memcpy(hmac_key, k, 32);
            if (len < 32) {
                for (int i = len; i < 32; i++) hmac_key[i] = key[i % len];
            }
        }
    }

    int encrypt(const unsigned char* input, int len, unsigned char* output, uint32_t counter) {
        if (len > GCM_PAYLOAD_MAX) return -1;

        unsigned char iv[16];
        int64_t us = esp_timer_get_time();
        uint32_t epoch = us > 0 ? (uint32_t)(us / 1000000) : counter;

        memcpy(iv, &epoch, 4);
        memcpy(iv + 4, &counter, 4);
        memset(iv + 8, 0, 8);

        memcpy(output, &counter, 4);
        memcpy(output + 4, input, len);

        unsigned char hash[32];
        computeHmac(hmac_key, output, len + 4, hash);
        memcpy(output + len + 4, hash, GCM_TAG_COMPACT);

        return len + 4 + GCM_TAG_COMPACT;
    }

    int decrypt(const unsigned char* input, int len, unsigned char* output, uint32_t* last_counter) {
        if (len < 4 + GCM_TAG_COMPACT) return -1;

        int ciphertext_len = len - GCM_TAG_COMPACT;
        uint32_t packet_counter;

        memcpy(&packet_counter, input, 4);

        if (last_counter && packet_counter <= *last_counter) {
            return -2;
        }

        unsigned char tag[16];
        memcpy(tag, input + ciphertext_len, GCM_TAG_COMPACT);

        unsigned char hash[32];
        computeHmac(hmac_key, input, ciphertext_len, hash);

        volatile unsigned char diff = 0;
        for (int i = 0; i < GCM_TAG_COMPACT; i++) {
            diff |= tag[i] ^ hash[i];
        }
        if (diff != 0) {
            return -1;
        }

        memcpy(output, input + 4, ciphertext_len - 4);

        if (last_counter) {
            *last_counter = packet_counter;
        }
        return ciphertext_len - 4;
    }

    int encrypt_simple(const unsigned char* plaintext, int len, unsigned char* output, const unsigned char* iv_in) {
        unsigned char hash[32];
        computeHmac(hmac_key, plaintext, len, hash);
        memcpy(output, plaintext, len);
        memcpy(output + len, hash, GCM_TAG_COMPACT);
        return len + GCM_TAG_COMPACT;
    }

    int decrypt_simple(const unsigned char* input, int len, unsigned char* output, const unsigned char* iv_in) {
        int ciphertext_len = len - GCM_TAG_COMPACT;

        unsigned char tag[16];
        memcpy(tag, input + ciphertext_len, GCM_TAG_COMPACT);

        unsigned char hash[32];
        computeHmac(hmac_key, input, ciphertext_len, hash);

        volatile unsigned char diff = 0;
        for (int i = 0; i < GCM_TAG_COMPACT; i++) {
            diff |= tag[i] ^ hash[i];
        }
        if (diff != 0) {
            return -1;
        }

        memcpy(output, input, ciphertext_len);
        return ciphertext_len;
    }
};

class SecurePacket {
private:
    uint32_t tx_counter;
    uint32_t rx_counter;
    uint32_t last_valid_counter;

public:
    SecurePacket() : tx_counter(0), rx_counter(0), last_valid_counter(0) {}

    uint32_t getNextCounter() {
        return ++tx_counter;
    }

    bool isValidCounter(uint32_t counter) {
        return counter > last_valid_counter;
    }

    void updateValidCounter(uint32_t counter) {
        if (counter > last_valid_counter) {
            last_valid_counter = counter;
        }
    }

    uint32_t getTXCounter() { return tx_counter; }
    uint32_t getRXCounter() { return rx_counter; }

    void reset() {
        tx_counter = 0;
        rx_counter = 0;
        last_valid_counter = 0;
    }
};

#endif