// crypto_hmac.h - HMAC-SHA256 Real Packet Authentication
// Garante integridade e autenticidade dos pacotes LoRa com HMAC-SHA256 verdadeiro

#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <stdint.h>
#include <string.h>
#include <mbedtls/md.h>

#define HMAC_SIGNATURE_SIZE 32  // SHA-256 = 32 bytes

class PacketAuthenticator {
public:
  // Cria assinatura HMAC-SHA256 para pacote
  static void sign(const byte* key, int keylen, const byte* packet, int pktlen, byte* signature) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, key, keylen);
    mbedtls_md_hmac_update(&ctx, packet, pktlen);
    mbedtls_md_hmac_finish(&ctx, signature);
    mbedtls_md_free(&ctx);
  }

  // Verifica se assinatura é válida (constant-time comparison)
  static bool verify(const byte* key, int keylen, const byte* packet, int pktlen, const byte* signature) {
    byte computed[HMAC_SIGNATURE_SIZE];
    sign(key, keylen, packet, pktlen, computed);

    // Constant-time comparison para evitar timing attacks
    volatile uint8_t result = 0;
    for (int i = 0; i < HMAC_SIGNATURE_SIZE; i++) {
      result |= computed[i] ^ signature[i];
    }
    return result == 0;
  }

  // Version legacy (8 bytes only) para backward compatibility
  static void signCompact(const byte* key, int keylen, const byte* packet, int pktlen, byte* signature) {
    byte full_sig[HMAC_SIGNATURE_SIZE];
    sign(key, keylen, packet, pktlen, full_sig);
    // Usa apenas os primeiros 8 bytes
    memcpy(signature, full_sig, 8);
  }

  static bool verifyCompact(const byte* key, int keylen, const byte* packet, int pktlen, const byte* signature) {
    byte computed[HMAC_SIGNATURE_SIZE];
    sign(key, keylen, packet, pktlen, computed);

    // Constant-time comparison dos primeiros 8 bytes
    volatile uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
      result |= computed[i] ^ signature[i];
    }
    return result == 0;
  }
};

#endif // CRYPTO_HMAC_H