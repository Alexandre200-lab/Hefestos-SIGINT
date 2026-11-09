// totp_auth.h - TOTP (RFC 6238) com 2FA real - v5.0.0
//
// v4.x: o arquivo existia mas NUNCA era included por nenhum sketch. O
// README e o OPERATION_MANUAL afirmavam "2FA TOTP" enquanto o /login
// verificava apenas usuario e senha. v5: TOTP e' obrigatório no login.
//
// Correcoes:
//   - comparacao do codigo em tempo constante
//   - nao aceita codigos com caracteres nao numericos (a v4 pulava-os,
//     fazendo "abcdef" virar 0 e potentially casar)
//   - protecao contra replay do mesmo passo de 30s (codigo usado 2x e' rejeitado)
//   - base32 ENCODE (a v4 so decodificava; o operador nao tinha como
//     cadastrar o segredo no authenticator)
#ifndef HEF_TOTP_AUTH_H
#define HEF_TOTP_AUTH_H

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <esp_random.h>
#include <mbedtls/md.h>

#define HEF_TOTP_SECRET_MAX 32
#define HEF_TOTP_DIGITS     6
#define HEF_TOTP_PERIOD     30
#define HEF_TOTP_WINDOW     1     // passos aceitos para tras

class TotpAuth {
private:
    uint8_t secret_[HEF_TOTP_SECRET_MAX];
    size_t  secretLen_;
    uint32_t lastUsedCounter_;
    bool     haveLastUsed_;

    static const char* base32Alphabet() { return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; }

    static bool base32Decode(const char* in, size_t inLen, uint8_t* out, size_t outCap, size_t* outLen) {
        uint32_t buffer = 0;
        int bits = 0;
        size_t o = 0;
        for (size_t i = 0; i < inLen && in[i]; i++) {
            const char* p = strchr(base32Alphabet(), in[i]);
            if (!p || in[i] == '=') continue;
            uint32_t v = (uint32_t)(p - base32Alphabet());
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (o >= outCap) return false;
                out[o++] = (uint8_t)((buffer >> bits) & 0xFF);
            }
        }
        *outLen = o;
        return o > 0;
    }

    static void base32Encode(const uint8_t* in, size_t inLen, char* out, size_t outCap) {
        uint32_t buffer = 0;
        int bits = 0;
        size_t o = 0;
        for (size_t i = 0; i < inLen; i++) {
            buffer = (buffer << 8) | in[i];
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                if (o + 1 >= outCap) { if (outCap) out[o] = 0; return; }
                out[o++] = base32Alphabet()[(buffer >> bits) & 0x1F];
            }
        }
        if (bits > 0 && o + 1 < outCap) {
            out[o++] = base32Alphabet()[(buffer << (5 - bits)) & 0x1F];
        }
        if (outCap) out[o] = 0;
    }

    uint32_t generateForCounter(uint32_t counter, uint8_t* hashOut) const {
        uint8_t cb[8];
        for (int i = 0; i < 8; i++) cb[i] = (uint8_t)(counter >> (56 - 8 * i));

        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md, 1);
        mbedtls_md_hmac_starts(&ctx, secret_, secretLen_);
        mbedtls_md_hmac_update(&ctx, cb, 8);
        mbedtls_md_hmac_finish(&ctx, hashOut);
        mbedtls_md_free(&ctx);

        uint8_t offset = hashOut[19] & 0x0F;
        uint32_t code = ((uint32_t)(hashOut[offset] & 0x7F) << 24) |
                        ((uint32_t)hashOut[offset + 1] << 16) |
                        ((uint32_t)hashOut[offset + 2] << 8) |
                        ((uint32_t)hashOut[offset + 3]);
        return code % 1000000UL;
    }

public:
    TotpAuth() : secretLen_(0), lastUsedCounter_(0), haveLastUsed_(false) {
        memset(secret_, 0, sizeof(secret_));
    }

    void setSecretRaw(const uint8_t* raw, size_t len) {
        if (!raw || len == 0 || len > HEF_TOTP_SECRET_MAX) return;
        memcpy(secret_, raw, len);
        secretLen_ = len;
    }

    void setSecretBase32(const char* b32) {
        size_t outLen = 0;
        if (base32Decode(b32, strlen(b32), secret_, sizeof(secret_), &outLen)) {
            secretLen_ = outLen;
        }
    }

    bool hasSecret() const { return secretLen_ > 0; }

    void generateRandomSecret(size_t len = 20) {
        if (len == 0 || len > HEF_TOTP_SECRET_MAX) len = 20;
        esp_fill_random(secret_, len);
        secretLen_ = len;
    }

    void exportBase32(char* out, size_t outCap) const {
        if (!out || outCap == 0) return;
        base32Encode(secret_, secretLen_, out, outCap);
    }

    void buildOtpAuthUri(char* out, size_t outCap, const char* issuer, const char* account) const {
        char b32[80];
        exportBase32(b32, sizeof(b32));
        snprintf(out, outCap,
                 "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                 issuer, account, b32, issuer, HEF_TOTP_DIGITS, HEF_TOTP_PERIOD);
    }

    // Verifica o codigo. Rejeita replay do mesmo passo de tempo.
    bool verify(const char* code, uint32_t unixTime) {
        if (!code || secretLen_ == 0) return false;

        // precisa ter exatamente HEF_TOTP_DIGITS digitos numericos
        if (strlen(code) != HEF_TOTP_DIGITS) return false;
        uint32_t value = 0;
        for (int i = 0; i < HEF_TOTP_DIGITS; i++) {
            if (code[i] < '0' || code[i] > '9') return false;
            value = value * 10 + (uint32_t)(code[i] - '0');
        }

        uint32_t base = unixTime / HEF_TOTP_PERIOD;
        uint8_t hash[20];

        for (int step = -HEF_TOTP_WINDOW; step <= HEF_TOTP_WINDOW; step++) {
            uint32_t counter = (uint32_t)((int32_t)base + step);
            uint32_t valid = generateForCounter(counter, hash);
            if (valid == value) {
                if (haveLastUsed_ && counter <= lastUsedCounter_) return false; // replay
                lastUsedCounter_ = counter;
                haveLastUsed_ = true;
                return true;
            }
        }
        return false;
    }

    // True se o relogio do dispositivo parece sincronizado (necessario
    // para TOTP funcionar).
    static bool clockLooksValid(uint32_t unixTime) {
        return unixTime > 1704067200UL; // 01/01/2024
    }
};

#endif // HEF_TOTP_AUTH_H
