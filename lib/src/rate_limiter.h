// rate_limiter.h - Limitacao de taxa por cliente (v5.0.0)
//
// CORRECOES (v4.x):
//   - A v4.x mantinha no maximo 8 clientes com hash FNV-1a do IP. Com o
//     roteador de campo, o ESP32 via softAP recebe enderecos IP que se
//     reutilizam; o hash colidia e o bucket era compartilhado, permitindo
//     que um atacante bloqueasse o operador.
//   - Na v4.x o rate limit era aplicado ANTES da autenticacao em
//     /sintonizar, entao um anonimo consumia a cota do operador.
//   - Cooldown de 100 ms global bloqueava o proprio dashboard.
//
// v5:
//   - Buckets por IP real (o IP e' a chave de transporte no softAP; nao e
//     gravado em disco e nao sai do dispositivo).
//   - Duas politicas independentes: LOGIN (por IP, contra brute force) e
//     CMD (por sessao autenticada, contra abuso/DoS).
//   - Janela deslizante real (token bucket) em vez de janela fixa.
#ifndef HEF_RATE_LIMITER_H
#define HEF_RATE_LIMITER_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"

struct RateBucket {
    uint32_t    ip;          // IP como uint32 (host order)
    float       tokens;
    uint32_t    lastRefillMs;
    bool        active;
    uint32_t    blockedUntilMs;
    uint32_t    lastOpMs;
};

class RateLimiter {
private:
    RateBucket buckets_[RATE_MAX_CLIENTS];
    uint32_t   bucketCount_;

    float capacity_;
    float refillPerSec_;
    uint32_t cooldownMs_;
    bool     useCooldown_;

    uint32_t now() const { return (uint32_t)millis(); }

    int findOrCreate(uint32_t ip) {
        for (uint32_t i = 0; i < RATE_MAX_CLIENTS; i++) {
            if (buckets_[i].active && buckets_[i].ip == ip) return (int)i;
        }
        // LRU: substitui o bucket mais antigo (menor lastRefillMs).
        int victim = -1;
        for (uint32_t i = 0; i < RATE_MAX_CLIENTS; i++) {
            if (!buckets_[i].active) { victim = (int)i; break; }
            if (victim < 0 || buckets_[i].lastRefillMs < buckets_[victim].lastRefillMs) {
                victim = (int)i;
            }
        }
        if (victim < 0) return -1;
        buckets_[victim].active        = true;
        buckets_[victim].ip            = ip;
        buckets_[victim].tokens        = capacity_;
        buckets_[victim].lastRefillMs  = now();
        buckets_[victim].blockedUntilMs = 0;
        buckets_[victim].lastOpMs       = 0;
        return victim;
    }

    void refill(RateBucket* b) {
        uint32_t t = now();
        uint32_t dt = t - b->lastRefillMs;
        if (dt == 0) return;
        b->lastRefillMs = t;
        float add = (refillPerSec_ * (float)dt) / 1000.0f;
        b->tokens += add;
        if (b->tokens > capacity_) b->tokens = capacity_;
    }

public:
    // bucket: numero de operacoes permitidas por janela
    // windowMs: tamanho da janela
    // cooldownMs: intervalo minimo entre operacoes (0 = sem cooldown)
    RateLimiter(uint32_t bucket, uint32_t windowMs, uint32_t cooldownMs = 0)
        : bucketCount_(0), capacity_((float)bucket),
          refillPerSec_((float)bucket * 1000.0f / (float)windowMs),
          cooldownMs_(cooldownMs), useCooldown_(cooldownMs > 0) {
        memset(buckets_, 0, sizeof(buckets_));
    }

    void reset() {
        memset(buckets_, 0, sizeof(buckets_));
        bucketCount_ = 0;
    }

    // Retorna true se a operacao for permitida.
    bool allow(uint32_t ip) {
        int idx = findOrCreate(ip);
        if (idx < 0) return false;
        RateBucket* b = &buckets_[idx];

        uint32_t t = now();
        if (b->blockedUntilMs != 0 && t < b->blockedUntilMs) return false;

        refill(b);
        if (b->tokens < 1.0f) return false;
        b->tokens -= 1.0f;
        return true;
    }

    // Bloqueia temporariamente o cliente (usado em falha de login).
    void block(uint32_t ip, uint32_t durationMs) {
        int idx = findOrCreate(ip);
        if (idx < 0) return;
        buckets_[idx].blockedUntilMs = now() + durationMs;
        buckets_[idx].tokens = 0.0f;
    }

    bool isBlocked(uint32_t ip) {
        for (uint32_t i = 0; i < RATE_MAX_CLIENTS; i++) {
            if (buckets_[i].active && buckets_[i].ip == ip) {
                uint32_t until = buckets_[i].blockedUntilMs;
                if (until == 0) return false;
                if (now() >= until) { buckets_[i].blockedUntilMs = 0; return false; }
                return true;
            }
        }
        return false;
    }

    // Cooldown entre operacoes, para impedir rajadas (usado nas rotas
    // autenticadas). O cooldown e' por cliente, nao global.
    bool allowWithCooldown(uint32_t ip) {
        int idx = findOrCreate(ip);
        if (idx < 0) return false;
        RateBucket* b = &buckets_[idx];

        uint32_t t = now();
        if (b->blockedUntilMs != 0 && t < b->blockedUntilMs) return false;

        refill(b);
        if (b->tokens < 1.0f) return false;
        if (useCooldown_ && b->lastOpMs != 0 &&
            (t - b->lastOpMs) < cooldownMs_) {
            return false;
        }
        b->tokens -= 1.0f;
        b->lastOpMs = t;
        return true;
    }

    float tokensRemaining(uint32_t ip) {
        for (uint32_t i = 0; i < RATE_MAX_CLIENTS; i++) {
            if (buckets_[i].active && buckets_[i].ip == ip) {
                refill(&buckets_[i]);
                return buckets_[i].tokens;
            }
        }
        return capacity_;
    }
};

// Converte IPAddress em uint32 (host order) para usar como chave de bucket.
inline uint32_t ipToKey(const IPAddress& ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  | (uint32_t)ip[3];
}

#endif // HEF_RATE_LIMITER_H
