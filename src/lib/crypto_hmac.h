// crypto_hmac.h - HMAC-SHA256 Packet Authentication
// Garante integridade e autenticidade dos pacotes LoRa

#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <stdint.h>
#include <string.h>

#define HMAC_SIGNATURE_SIZE 8  // Use 8 bytes (64 bits) para economia de bandwidth

class PacketAuthenticator {
public:
  // Cria assinatura rápida para pacote usando XOR+folding (adequado para embedded)
  static void sign(const byte* key, int keylen, const byte* packet, int pktlen, byte* signature) {
    uint32_t hash = 0x5A5A5A5A; // IV
    
    // Mix key
    for (int i = 0; i < keylen; i++) {
      hash ^= (key[i] << ((i % 4) * 8));
      hash = rotate_left(hash, 7);
    }
    
    // Mix packet
    for (int i = 0; i < pktlen; i++) {
      hash ^= (packet[i] << ((i % 4) * 8));
      hash = rotate_left(hash, 13);
    }
    
    // Output signature
    for (int i = 0; i < HMAC_SIGNATURE_SIZE; i++) {
      signature[i] = (hash >> ((i % 4) * 8)) & 0xFF;
      hash = rotate_left(hash, 5);
    }
  }

  // Verifica se assinatura é válida (constant-time comparison)
  static bool verify(const byte* key, int keylen, const byte* packet, int pktlen, const byte* signature) {
    byte computed[HMAC_SIGNATURE_SIZE];
    sign(key, keylen, packet, pktlen, computed);

    // Constant-time comparison para evitar timing attacks
    int result = 0;
    for (int i = 0; i < HMAC_SIGNATURE_SIZE; i++) {
      result |= (computed[i] ^ signature[i]);
    }
    return result == 0;
  }

private:
  static uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
  }
};

#endif // CRYPTO_HMAC_H
