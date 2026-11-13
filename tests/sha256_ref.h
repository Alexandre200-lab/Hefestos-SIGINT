// =====================================================================
// tests/sha256_ref.h
//
// SHA-256 de REFERENCIA para os testes de host (item 1.6).
//
// O `HefLogBatch` recebe a funcao de hash INJETADA: no firmware e' o
// mbedtls; nos testes de host e' esta implementacao. Para que o teste
// da cadeia tenha valor, esta implementacao e' ela mesma validada,
// no proprio teste, contra os vetores oficiais do NIST
// (FIPS 180-4 / "NIST Cryptographic Algorithm Validation Program"):
//   - "abc"
//   - mensagem vazia
//   - "abcdbcdecdef..." (448 bits)
//   - 1 milhao de 'a'
// Se a referencia divergir do NIST, o teste falha ANTES de exercitar
// a cadeia — nunca se valida uma cadeia com um hash que nao e' o
// padrao.
//
// Roda no HOST (g++), sem hardware. Nao use no firmware.
// =====================================================================
#ifndef HEF_SHA256_REF_H
#define HEF_SHA256_REF_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace hefref {

struct Sha256Ctx {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  block[64];
    size_t   used;
};

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void compress(Sha256Ctx& c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

static void init(Sha256Ctx& c) {
    static const uint32_t H0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    memcpy(c.h, H0, sizeof(H0));
    c.bits = 0;
    c.used = 0;
}

static void update(Sha256Ctx& c, const uint8_t* data, size_t len) {
    c.bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c.used;
        if (take > len) take = len;
        memcpy(c.block + c.used, data, take);
        c.used += take;
        data += take;
        len -= take;
        if (c.used == 64) {
            compress(c, c.block);
            c.used = 0;
        }
    }
}

static void final_(Sha256Ctx& c, uint8_t* out) {
    uint64_t bits = c.bits;
    uint8_t pad = 0x80;
    update(c, &pad, 1);
    uint8_t zero = 0;
    while (c.used != 56) update(c, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    // O update do padding nao pode contar nos bits finais: bits ja foi
    // salvo antes. Mas o update() acima somou os bytes de padding —
    // por isso usamos `bits` salvo, nao c.bits.
    memcpy(c.block + 56, lenb, 8);
    compress(c, c.block);
    c.used = 0;
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c.h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c.h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c.h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c.h[i]);
    }
}

static void sha256(const uint8_t* data, size_t len, uint8_t* out) {
    Sha256Ctx c;
    init(c);
    update(c, data, len);
    final_(c, out);
}

// ---------------------------------------------------------------------
// Vetores NIST (FIPS 180-4, exemplos oficiais)
// ---------------------------------------------------------------------
static bool selfTest() {
    uint8_t d[32];

    // 1) "abc" — SHA3? nao: FIPS 180-4 exemplo 1.
    sha256((const uint8_t*)"abc", 3, d);
    static const uint8_t e1[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,
        0x5D,0xAE,0x22,0x23,0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
        0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
    };
    if (memcmp(d, e1, 32) != 0) return false;

    // 2) Mensagem vazia.
    sha256((const uint8_t*)"", 0, d);
    static const uint8_t e2[32] = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,0x9A,0xFB,0xF4,0xC8,
        0x99,0x6F,0xB9,0x24,0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };
    if (memcmp(d, e2, 32) != 0) return false;

    // 3) Mensagem de 448 bits (FIPS 180-4, exemplo 2).
    static const char* m3 =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t*)m3, strlen(m3), d);
    static const uint8_t e3[32] = {
        0x24,0x8D,0x6A,0x61,0xD2,0x06,0x38,0xB8,0xE5,0xC0,0x26,0x93,
        0x0C,0x3E,0x60,0x39,0xA3,0x3C,0xE4,0x59,0x64,0xFF,0x21,0x67,
        0xF6,0xEC,0xED,0xD4,0x19,0xDB,0x06,0xC1
    };
    if (memcmp(d, e3, 32) != 0) return false;

    // 4) 1 milhao de 'a' (FIPS 180-4, exemplo 3) — em blocos, para
    //    exercitar o buffering entre updates.
    Sha256Ctx c;
    init(c);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    for (int i = 0; i < 1000; i++) update(c, chunk, sizeof(chunk));
    final_(c, d);
    static const uint8_t e4[32] = {
        0xCD,0xC7,0x6E,0x5C,0x99,0x14,0xFB,0x92,0x81,0xA1,0xC7,0xE2,
        0x84,0xD7,0x3E,0x67,0xF1,0x80,0x9A,0x48,0xA4,0x97,0x20,0x0E,
        0x04,0x6D,0x39,0xCC,0xC7,0x11,0x2C,0xD0
    };
    if (memcmp(d, e4, 32) != 0) return false;

    return true;
}

} // namespace hefref

#endif // HEF_SHA256_REF_H
