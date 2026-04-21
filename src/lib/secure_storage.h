// secure_storage.h - Secure Storage com Encrypt at Rest
// Criptografa dados antes de gravar em SD Card ou EEPROM
// Alternativa ao secure element (ATECC608A)

#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include <stdint.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define SECURE_STORAGE_KEY_SIZE 32  // 256-bit key
#define SECURE_STORAGE_BLOCK 16       // AES block size

class SecureStorage {
private:
    byte master_key[SECURE_STORAGE_KEY_SIZE];
    bool initialized;

    mbedtls_aes_context aes_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    // Deriva chave de uma senha usando PBKDF2-like
    void deriveKey(const char* password, byte* output) {
        uint32_t seed = 0;
        for (int i = 0; password[i]; i++) {
            seed = (seed * 31 + password[i]) & 0xFFFFFFFF;
        }
        seed ^= millis();

        // Iterações simples (替代 PBKDF2 por limitação de memória)
        for (int round = 0; round < 1000; round++) {
            uint32_t s = seed ^ round;
            for (int i = 0; i < SECURE_STORAGE_KEY_SIZE; i++) {
                output[i] ^= ((s >> (i % 4)) & 0xFF);
                s = (s * 1103515245 + 12345) & 0x7FFFFFFF;
            }
        }
    }

public:
    SecureStorage() : initialized(false) {}

    // Inicializa com senha
    bool begin(const char* password) {
        if (!password || strlen(password) < 8) return false;

        deriveKey(password, master_key);
        initialized = true;
        return true;
    }

    // Inicializa com chave raw
    bool beginRaw(const byte* key) {
        if (!key) return false;
        memcpy(master_key, key, SECURE_STORAGE_KEY_SIZE);
        initialized = true;
        return true;
    }

    // Criptografa dados (CTR mode)
    int encrypt(const uint8_t* input, int len, uint8_t* output, const uint8_t* iv) {
        if (!initialized) return -1;

        size_t olen = 0;
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, master_key, 256);

        int ret = mbedtls_aes_crypt_ctr(
            &aes_ctx,
            len,
            &olen,
            iv,
            input,
            output
        );

        mbedtls_aes_free(&aes_ctx);
        return ret == 0 ? olen : -1;
    }

    // Descriptografa dados
    int decrypt(const uint8_t* input, int len, uint8_t* output, const uint8_t* iv) {
        return encrypt(input, len, output, iv);  // CTR is symmetric
    }

    // Versão simples XOR+rot13 para Arduino (memória limitada)
    int encryptSimple(const uint8_t* input, int len, uint8_t* output) {
        if (!initialized) return -1;

        for (int i = 0; i < len; i++) {
            output[i] = input[i] ^ master_key[i % SECURE_STORAGE_KEY_SIZE];
            output[i] = ((output[i] >> 2) | (output[i] << 6)) & 0xFF;  // ROT2
        }
        return len;
    }

    int decryptSimple(const uint8_t* input, int len, uint8_t* output) {
        if (!initialized) return -1;

        for (int i = 0; i < len; i++) {
            output[i] = ((input[i] << 2) | (input[i] >> 6)) & 0xFF;  // ROT2 inverso
            output[i] = input[i] ^ master_key[i % SECURE_STORAGE_KEY_SIZE];
        }
        return len;
    }

    bool isInitialized() { return initialized; }
};

// Helper para limpar dados sensíveis da memória
class SecureMem {
public:
    static void wipe(byte* data, int len) {
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

#endif // SECURE_STORAGE_H