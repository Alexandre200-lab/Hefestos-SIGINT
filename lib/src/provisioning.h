// provisioning.h - Derivacao de chaves por no (HKDF-SHA256) - v5.0.0
//
// PROBLEMA RESOLVIDO (v4.x):
//   Na v4.x cada chip derivava sua chave do proprio MAC do efuse. Como o
//   MAC e' unico por chip, Node1 e Node2 NUNCA podiam compartilhar chave:
//   o link LoRa estava morto de fabrica e nao existia caminho de
//   provisionamento (setAESKey() nunca era chamado).
//
// MODELO v5:
//   1. O operador establish um PSK de deploy (32 bytes) em cada no,
//      uma unica vez (console serial na primeira operacao).
//   2. Cada no deriva sua chave de link de forma DETERMINISTICA:
//        key_node = HKDF-SHA256(ikm = PSK, salt = node_id (2 bytes LE),
//                                info = "hefestos-v5/link/aes256")
//   3. O Node2 mantem a lista de node_ids enrolled; para cada peer, deriva
//      a mesma chave a partir do mesmo PSK.
//   4. O PSK pode ser apagado do no apos a derivacao das chaves locais
//      (no Node1); no Node2 ele e' necessario para derivar chaves de novos
//      peers, mas pode ser rotacionado.
//
// Vantagens:
//   - Uma unica chave de deploy, chaves distintas por no.
//   - Comprometimento de um no nao expoe a chave de outro no.
//   - Rotacao via novo PSK + re-enrollment.
//   - Nenhuma chave de link e' transmitted em claro.
#ifndef HEF_PROVISIONING_H
#define HEF_PROVISIONING_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"
#include "crypto_gcm.h"

// Deriva a chave de link de um no a partir do PSK de deploy.
inline bool deriveNodeKey(const uint8_t* psk, size_t pskLen,
                           uint16_t nodeId,
                           uint8_t* outKey, size_t outLen = HEF_KEY_LEN) {
    if (!psk || pskLen < 16 || !outKey || outLen != HEF_KEY_LEN) return false;
    uint8_t salt[2];
    salt[0] = (uint8_t)(nodeId & 0xFF);
    salt[1] = (uint8_t)(nodeId >> 8);
    const uint8_t info[] = "hefestos-v5/link/aes256";
    return hefHkdfSha256(psk, pskLen, salt, sizeof(salt),
                         info, sizeof(info) - 1, outKey, outLen);
}

// Deriva um epoch novo (16 bits) a partir de entropia do hardware,
// misturado com o node_id e o timestamp de boot para reduzir colisao.
inline uint16_t deriveEpoch(uint16_t nodeId, uint32_t bootMillis) {
    uint8_t seed[16];
    esp_fill_random(seed, sizeof(seed));
    uint8_t input[22];
    memcpy(input, seed, 16);
    input[16] = (uint8_t)(nodeId & 0xFF);
    input[17] = (uint8_t)(nodeId >> 8);
    input[18] = (uint8_t)(bootMillis & 0xFF);
    input[19] = (uint8_t)((bootMillis >> 8) & 0xFF);
    input[20] = (uint8_t)((bootMillis >> 16) & 0xFF);
    input[21] = (uint8_t)((bootMillis >> 24) & 0xFF);
    uint8_t digest[32];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return (uint16_t)(nodeId ^ 0x5A5A);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, input, sizeof(input));
    mbedtls_md_finish(&ctx, digest);
    mbedtls_md_free(&ctx);
    uint16_t epoch = (uint16_t)(((uint16_t)digest[0] << 8) | digest[1]);
    if (epoch == 0) epoch = 1;
    return epoch;
}

// Converte hex ASCII (<=64 chars) em bytes. Retorna bytes gravados ou -1.
inline int hexToBytes(const char* hex, uint8_t* out, size_t outCap) {
    if (!hex || !out) return -1;
    size_t len = strlen(hex);
    if (len == 0 || (len % 2) != 0) return -1;
    if (len / 2 > outCap) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        int hv, lv;
        if (hi >= '0' && hi <= '9') hv = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hv = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hv = hi - 'A' + 10;
        else return -1;
        if (lo >= '0' && lo <= '9') lv = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lv = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lv = lo - 'A' + 10;
        else return -1;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return (int)(len / 2);
}

inline void bytesToHex(const uint8_t* in, size_t len, char* out, size_t outCap) {
    static const char* hexd = "0123456789ABCDEF";
    if (!in || !out || outCap < len * 2 + 1) return;
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hexd[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexd[in[i] & 0x0F];
    }
    out[len * 2] = 0;
}

#endif // HEF_PROVISIONING_H
