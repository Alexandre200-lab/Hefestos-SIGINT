// totp_auth.h - TOTP 2FA Authentication
// Implementa Time-based One-Time Password (RFC 6238)
// Compatível com Google Authenticator, Authy, etc.

#ifndef TOTP_AUTH_H
#define TOTP_AUTH_H

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <mbedtls/md.h>

#define TOTP_SECRET_MAX 32
#define TOTP_DIGITS 6       // 6 dígitos (padrão)
#define TOTP_PERIOD 30      // 30 segundos (padrão)
#define TOTP_WINDOW 1       // Janela de 1 passo (aceita anterior)

// Base32 decoding helpers
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_decode(const char* input, int len, uint8_t* output) {
    int buffer = 0;
    int bits_left = 0;
    int output_index = 0;

    for (int i = 0; i < len && input[i]; i++) {
        char c = input[i];
        int value = -1;

        for (int j = 0; j < 32; j++) {
            if (base32_alphabet[j] == c) {
                value = j;
                break;
            }
        }

        if (value < 0) continue;

        buffer = (buffer << 5) | value;
        bits_left += 5;

        if (bits_left >= 8) {
            bits_left -= 8;
            output[output_index++] = (buffer >> bits_left) & 0xFF;
        }
    }

    return output_index;
}

// TOTP Generator
class TOTPAuth {
private:
    uint8_t secret[TOTP_SECRET_MAX];
    int secret_len;
    uint8_t hash[20];  // SHA1 output

    static uint32_t getUnixTime() {
        time_t now;
        struct tm timeinfo;
        time(&now);
        localtime_r(&now, &timeinfo);
        return (uint32_t)now;
    }

public:
    TOTPAuth() : secret_len(0) {
        memset(secret, 0, TOTP_SECRET_MAX);
    }

    // Configura segredo (base32 encoded)
    void setSecret(const char* base32_secret) {
        secret_len = base32_decode(base32_secret, strlen(base32_secret), secret);
    }

    // Configura segredo (raw bytes)
    void setSecretRaw(const uint8_t* raw_secret, int len) {
        if (len <= TOTP_SECRET_MAX) {
            memcpy(secret, raw_secret, len);
            secret_len = len;
        }
    }

    // Gera TOTP para timestamp específico
    uint32_t generate(uint32_t timestamp = 0) {
        if (secret_len == 0) return 0;

        if (timestamp == 0) {
            timestamp = getUnixTime();
        }

        uint32_t counter = timestamp / TOTP_PERIOD;

        return generateHMAC(counter);
    }

    // Verifica TOTP
    bool verify(const char* code) {
        uint32_t input_code = 0;
        
        for (int i = 0; i < TOTP_DIGITS && code[i]; i++) {
            if (code[i] >= '0' && code[i] <= '9') {
                input_code = input_code * 10 + (code[i] - '0');
            }
        }

        uint32_t valid_code = generate();
        
        if (input_code == valid_code) {
            return true;
        }

        // Verifica janela anterior
        for (int i = 1; i <= TOTP_WINDOW; i++) {
            valid_code = generate(getUnixTime() - i * TOTP_PERIOD);
            if (input_code == valid_code) {
                return true;
            }
        }

        return false;
    }

    // Gera URL QR para Google Authenticator
    void getQRUrl(const char* account, const char* issuer, char* output, int max_len) {
        snprintf(output, max_len,
            "otpauth://totp/%s:%s?secret=", 
            issuer, account);
        
        // Adicionar base32 encoded do segredo
        int pos = strlen(output);
        for (int i = 0; i < secret_len && pos < max_len - 2; i++) {
            int val = secret[i];
            output[pos++] = base32_alphabet[(val >> 3) & 0x1F];
            output[pos++] = base32_alphabet[(val << 2) & 0x1F];
        }
        output[pos] = '\0';
    }

private:
    uint32_t generateHMAC(uint32_t counter) {
        uint8_t counter_bytes[8];
        counter_bytes[0] = (counter >> 56) & 0xFF;
        counter_bytes[1] = (counter >> 48) & 0xFF;
        counter_bytes[2] = (counter >> 40) & 0xFF;
        counter_bytes[3] = (counter >> 32) & 0xFF;
        counter_bytes[4] = (counter >> 24) & 0xFF;
        counter_bytes[5] = (counter >> 16) & 0xFF;
        counter_bytes[6] = (counter >> 8) & 0xFF;
        counter_bytes[7] = counter & 0xFF;

        mbedtls_md_context_t md_ctx;
        mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
        mbedtls_md_init(&md_ctx);
        mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1);
        mbedtls_md_hmac_starts(&md_ctx, secret, secret_len);
        mbedtls_md_hmac_update(&md_ctx, counter_bytes, 8);
        mbedtls_md_hmac_finish(&md_ctx, hash);
        mbedtls_md_free(&md_ctx);

        int offset = hash[19] & 0x0F;
        uint32_t code = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     ((hash[offset + 3] & 0xFF));

        code = code % 1000000;
        return code;
    }
};

// Gestor de senhas TOTP múltiplas
class TOTPManager {
private:
    static const int MAX_ACCOUNTS = 5;
    struct TOTPAccount {
        char name[16];
        TOTPAuth totp;
        bool active;
    };
    TOTPAccount accounts[MAX_ACCOUNTS];
    int accounts_count;

public:
    TOTPManager() : accounts_count(0) {
        for (int i = 0; i < MAX_ACCOUNTS; i++) {
            accounts[i].active = false;
        }
    }

    bool addAccount(const char* name, const char* secret_base32) {
        for (int i = 0; i < MAX_ACCOUNTS; i++) {
            if (!accounts[i].active) {
                strncpy(accounts[i].name, name, 15);
                accounts[i].totp.setSecret(secret_base32);
                accounts[i].active = true;
                accounts_count++;
                return true;
            }
        }
        return false;
    }

    bool verify(const char* name, const char* code) {
        for (int i = 0; i < MAX_ACCOUNTS; i++) {
            if (accounts[i].active && strcmp(accounts[i].name, name) == 0) {
                return accounts[i].totp.verify(code);
            }
        }
        return false;
    }

    int getAccountCount() { return accounts_count; }
};

#endif // TOTP_AUTH_H