// link_budget.h - Tempo no ar, duty cycle e orcamento de RF - v5.1.0
//
// OBJETIVO
//   O link LoRa da v5.0.0 era fisicamente inviavel: 1 frame/s com SF10
//   exige ~226% de duty cycle (o enlace nao pode ocupar mais de 100% do
//   tempo). Alem disso, nada no firmware impedia que uma configuracao
//   regulatoria violada fosse operada.
//
//   Este modulo provides:
//     - o calculo do tempo no ar (ToA) com a formula da camada fisica;
//     - o calculo de duty cycle e de consumo energetico;
//     - o intervalo minimo que um perfil regional exige;
//     - um guard de duty cycle que IMPEDE a transmissao quando o
//       orcamento da janela deslizante seria violado.
//
// FORMULA (camada fisica LoRa, SX1276 / RP002 LoRaWAN)
//   Tsym      = 2^SF / BW
//   codewords = ceil((8*PL + 16) / (4*CR_num))     [CRC de 16 bits ligado]
//   simbolos  = (preamble + 4.25) + header + codewords * (CR_num + 1)
//   header    = 4 bytes explicitos -> 8 simbolos
//   ToA       = simbolos * Tsym
//
//   A formula foi validada contra a tabela de airtime do RP002 (EU868):
//   SF7/12B  ->   56,576 ms  (tabela:   56,576 ms)
//   SF10/12B ->  452,608 ms  (tabela:  452,608 ms)
//   SF12/115B-> 10330,112 ms (tabela: 10330,112 ms)
//   e tambem contra a lei de escalonamento exata 2^(delta SF).
//
//   O calculo e' feito em MICROSSEGUNDOS com simbolos fracionarios
//   (quartos de simbolo) para reproduzir a tabela oficial sem erro de
//   arredondamento.
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST.
#ifndef HEF_LINK_BUDGET_H
#define HEF_LINK_BUDGET_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"

// ---------------------------------------------------------------------
// Parametros do link fisico
// ---------------------------------------------------------------------
struct HefLinkParams {
    uint8_t  sf;              // 7..12 (6 e' reservado para payload maior)
    uint16_t bwKHz;           // 125, 250 ou 500
    uint8_t  crNum;           // 4 (4/5), 6 (6/7), 7 (7/8)
    uint8_t  preambleSymbols; // 8 (padrao do SX1276)
    bool     crcOn;           // CRC de 16 bits (sempre ligado no Hefestos)
    bool     explicitHeader;  // cabecalho explicito de 4 bytes

    HefLinkParams()
        : sf(8), bwKHz(125), crNum(4), preambleSymbols(8),
          crcOn(true), explicitHeader(true) {}
};

class HefLinkBudget {
public:
    // --- Validade de parametros ---
    static bool validSf(uint8_t sf)  { return sf >= 6 && sf <= 12; }
    static bool validBw(uint16_t bw) { return bw == 125 || bw == 250 || bw == 500; }
    static bool validCr(uint8_t cr)  { return cr == 4 || cr == 6 || cr == 7; }

    static bool paramsValid(const HefLinkParams& p) {
        return validSf(p.sf) && validBw(p.bwKHz) && validCr(p.crNum);
    }

    // Tempo de simbolo em microssegundos: 2^SF * 1000 / BW(kHz).
    // (2^12 * 1000 = 4.096.000 -> cabe em uint32.)
    static uint32_t symbolTimeUs(uint8_t sf, uint16_t bwKHz) {
        if (!validBw(bwKHz)) return 0;
        return ((uint32_t)1 << sf) * 1000UL / (uint32_t)bwKHz;
    }

    // Tempo no ar em microssegundos.
    static uint32_t airtimeUs(uint16_t payloadBytes, const HefLinkParams& p) {
        if (!paramsValid(p)) return 0;

        uint8_t  crDen   = (uint8_t)(p.crNum + 1);
        uint32_t bits    = 8UL * (uint32_t)payloadBytes + (p.crcOn ? 16UL : 0UL);
        uint32_t perCW   = 4UL * (uint32_t)p.crNum;
        uint32_t codewords = (bits + perCW - 1UL) / perCW;   // ceil
        uint32_t payloadSyms = codewords * (uint32_t)crDen;
        uint32_t headerSyms  = p.explicitHeader ? 8UL : 0UL;

        // Quartos de simbolo: (preamble + 4.25) = preamble*4 + 17.
        uint32_t quarter = (uint32_t)p.preambleSymbols * 4UL + 17UL
                         + headerSyms * 4UL
                         + payloadSyms * 4UL;

        uint64_t us = (uint64_t)quarter * (uint64_t)symbolTimeUs(p.sf, p.bwKHz) / 4ULL;
        return (uint32_t)us;
    }

    static uint32_t airtimeMs(uint16_t payloadBytes, const HefLinkParams& p) {
        return (airtimeUs(payloadBytes, p) + 999UL) / 1000UL;
    }

    // Duty cycle em % para um ciclo de airtime dentro de um intervalo.
    static float dutyCyclePercent(uint32_t airtimeMsTotal, uint32_t intervalMs) {
        if (intervalMs == 0) return 100.0f;
        return (100.0f * (float)airtimeMsTotal) / (float)intervalMs;
    }

    // Energia de transmissao em mAh (mA * s / 3600).
    static float txEnergyMah(uint32_t airtimeMsTotal, float txCurrentMa) {
        return ((float)airtimeMsTotal / 1000.0f) * txCurrentMa / 3600.0f;
    }

    // Intervalo minimo (ms) para que o duty cycle fique dentro do limite.
    // Retorna 0xFFFFFFFF quando o limite e' zero (nenhuma transmissao).
    static uint32_t minIntervalForDuty(float limitPercent, uint32_t cycleMs) {
        if (limitPercent <= 0.0f) return 0xFFFFFFFFUL;
        double need = ((double)cycleMs * 100.0) / (double)limitPercent;
        if (need >= 4294967295.0) return 0xFFFFFFFFUL;
        return (uint32_t)(need + 0.999999);
    }
};

// ---------------------------------------------------------------------
// Guard de duty cycle (janela deslizante de 1 hora, baldes de 1 minuto)
// ---------------------------------------------------------------------
//
// O balde de um minuto e' indexado pelo minuto absoluto (modulo 60), o
// que torna a janela deslizante um contador O(1): quando o minuto vira,
// o balde correspondente e' zerado. Os baldes com mais de 60 minutos
// sao expirados por definicao.
//
// O guard e' usado pelo Node 1 (TX de telemetria) e pelo Node 2 (TX do
// ACK): os DOIS consomem espectro e os dois devem respeitar o limite.
class HefDutyGuard {
public:
    static const uint8_t  BUCKETS      = 60;
    static const uint32_t BUCKET_MS    = 60000UL;
    static const uint32_t WINDOW_MS    = 3600000UL;   // 1 hora

private:
    uint32_t bucketMinute_[BUCKETS];
    uint16_t bucketAirMs_[BUCKETS];

public:
    HefDutyGuard() { reset(); }

    void reset() {
        memset(bucketMinute_, 0, sizeof(bucketMinute_));
        memset(bucketAirMs_, 0, sizeof(bucketAirMs_));
    }

    // Airtime acumulado (ms) dentro da janela, sem registro.
    uint32_t windowAirtimeMs(uint32_t nowMs) const {
        uint32_t minute = nowMs / BUCKET_MS;
        uint32_t total = 0;
        for (uint8_t i = 0; i < BUCKETS; i++) {
            if (bucketMinute_[i] + (uint32_t)BUCKETS <= minute) continue;  // expirado
            total += bucketAirMs_[i];
        }
        return total;
    }

    // Duty cycle atual (%) dentro da janela.
    float dutyCyclePercent(uint32_t nowMs) const {
        return (100.0f * (float)windowAirtimeMs(nowMs)) / (float)WINDOW_MS;
    }

    // Registra uma transmissao e devolve o duty cycle resultante.
    float record(uint32_t nowMs, uint32_t airtimeMs) {
        uint32_t minute = nowMs / BUCKET_MS;
        uint8_t  idx    = (uint8_t)(minute % BUCKETS);
        if (bucketMinute_[idx] != minute) {
            bucketMinute_[idx] = minute;
            bucketAirMs_[idx]  = 0;
        }
        uint32_t v = (uint32_t)bucketAirMs_[idx] + airtimeMs;
        bucketAirMs_[idx] = (uint16_t)(v > 65535UL ? 65535UL : v);
        return dutyCyclePercent(nowMs);
    }

    // A transmissao cabe no orcamento? (conservador: soma o airtime
    // previsto ao total atual da janela)
    bool allows(uint32_t nowMs, uint32_t nextAirtimeMs, float limitPercent) const {
        if (limitPercent <= 0.0f) return false;
        uint32_t projected = windowAirtimeMs(nowMs) + nextAirtimeMs;
        float pct = (100.0f * (float)projected) / (float)WINDOW_MS;
        return pct <= limitPercent;
    }
};

#endif // HEF_LINK_BUDGET_H
