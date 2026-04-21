// crypto_gcm.h - AES-GCM Authenticated Encryption
// Substitui HMAC+Básico por AEAD (Authenticated Encryption with Associated Data)
// Elimina vulnerabilidade de replay attack com nonce + counter

#ifndef CRYPTO_GCM_H
#define CRYPTO_GCM_H

#include <stdint.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/cipher.h>

#define GCM_KEY_SIZE 16        // AES-128
#define GCM_IV_SIZE 12        // 96 bits (recommendado)
#define GCM_TAG_SIZE 16       // 128 bits (full authentication)
#define GCM_TAG_COMPACT 8     // 64 bits (compact, para LoRa)
#define GCM_PAYLOAD_MAX 240    // Máximo payload após adicionar nonce+counter

class AESGCM {
private:
    byte key[GCM_KEY_SIZE];
    int key_len;

    mbedtls_gcm_context gcm_ctx;

public:
    AESGCM() : key_len(GCM_KEY_SIZE) {}

    void setKey(const byte* k, int len = GCM_KEY_SIZE) {
        if (len == GCM_KEY_SIZE) {
            memcpy(key, k, GCM_KEY_SIZE);
            key_len = len;
        }
    }

    // Criptografa com nonce automaticamente gerado (nao usa counter interno!)
    // Input: plaintext || nonce(12) || packet_counter(4)
    // Output: ciphertext || tag(8)
    int encrypt(const byte* input, int len, byte* output, uint32_t counter) {
        if (len > GCM_PAYLOAD_MAX) return -1;

        byte nonce[GCM_IV_SIZE];
        byte iv[GCM_IV_SIZE + 4];

        // Gera nonce único: timestamp || counter
        uint32_t ts = millis();
        memcpy(nonce, &ts, 4);
        memcpy(nonce + 4, &counter, 4);

        // Copia counter para output (para receptor verificar)
        memcpy(output, &counter, 4);

        // Copia plaintext após counter
        memcpy(output + 4, input, len);

        // Prepara IV para GCM
        memcpy(iv, nonce, GCM_IV_SIZE);

        // Inicializa GCM
        mbedtls_gcm_init(&gcm_ctx);
        mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_len * 8, key);

        // Encripta e autentica
        int ret = mbedtls_gcm_authenticate_encrypt(
            &gcm_ctx,
            GCM_IV_SIZE,
            iv,
            0, NULL,
            len + 4,
            output,
            len + 4,
            output + len + 4,
            GCM_TAG_COMPACT
        );

        mbedtls_gcm_free(&gcm_ctx);

        if (ret == 0) {
            return len + 4 + GCM_TAG_COMPACT;  // ciphertext + tag
        }
        return -1;
    }

    // Descriptografa e verifica autenticidade
    // Input: ciphertext || tag(8)
    // Output: plaintext (verifica counter no inicio)
    int decrypt(const byte* input, int len, byte* output, uint32_t* last_counter) {
        if (len < 4 + GCM_TAG_COMPACT) return -1;

        int ciphertext_len = len - GCM_TAG_COMPACT;
        uint32_t packet_counter;

        // Extrai counter do inicio do ciphertext
        memcpy(&packet_counter, input, 4);

        // Verifica é maior que ultimo
        if (last_counter && packet_counter <= *last_counter) {
            return -2;  // Replay attack detectado!
        }

        byte nonce[GCM_IV_SIZE];
        byte iv[GCM_IV_SIZE + 4];
        uint32_t ts = millis();

        // Reconstrui nonce (usa timestamp atual como aproximacao)
        memcpy(nonce, &ts, 4);
        memcpy(nonce + 4, &packet_counter, 4);

        // Prepara IV
        memcpy(iv, nonce, GCM_IV_SIZE);

        // Extrai ciphertext
        memcpy(output, input + 4, ciphertext_len - 4);

        // Inicializa GCM
        mbedtls_gcm_init(&gcm_ctx);
        mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_len * 8, key);

        // Descriptografa e verifica
        int ret = mbedtls_gcm_authenticated_decrypt(
            &gcm_ctx,
            GCM_IV_SIZE,
            iv,
            0, NULL,
            ciphertext_len,
            input + 4,
            ciphertext_len - 4,
            output,
            input + ciphertext_len,
            GCM_TAG_COMPACT
        );

        mbedtls_gcm_free(&gcm_ctx);

        if (ret == 0 && last_counter) {
            *last_counter = packet_counter;
            return ciphertext_len - 4;
        }
        return -1;
    }

    // Versao simples (sem AEAD) para debugging
    int encrypt_simple(const byte* plaintext, int len, byte* output, const byte* iv_in) {
        mbedtls_gcm_init(&gcm_ctx);
        mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_len * 8, key);

        int ret = mbedtls_gcm_encrypt_and_tag(
            &gcm_ctx,
            len,
            iv_in,
            0, NULL,
            plaintext,
            output,
            output + len,
            GCM_TAG_COMPACT
        );

        mbedtls_gcm_free(&gcm_ctx);
        return ret == 0 ? len + GCM_TAG_COMPACT : -1;
    }

    int decrypt_simple(const byte* input, int len, byte* output, const byte* iv_in) {
        int ciphertext_len = len - GCM_TAG_COMPACT;

        mbedtls_gcm_init(&gcm_ctx);
        mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_len * 8, key);

        int ret = mbedtls_gcm_decrypt_auth_verify(
            &gcm_ctx,
            ciphertext_len,
            iv_in,
            0, NULL,
            input,
            output,
            input + ciphertext_len,
            GCM_TAG_COMPACT
        );

        mbedtls_gcm_free(&gcm_ctx);
        return ret == 0 ? ciphertext_len : -1;
    }
};

// Helper class para gerenciamento de nonce/counter
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

#endif // CRYPTO_GCM_H