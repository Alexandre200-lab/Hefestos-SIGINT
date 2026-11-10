// reset_tracker.h - Causa de reinicio e contadores de operacao - v5.1.0
//
// OBJETIVO
//   Item 1.4 do plano de escala: um dispositivo militar precisa saber
//   COMO reiniciou. Um brownout (queda de alimentacao) e um watchdog
//   (travamento do loop) sao falhas de naturezas completamente
//   diferentes — uma e' problema de energia, a outra e' bug de software —
//   e tratam-se de formas diferentes.
//
//   A v5.0.0 nao registrava NADA: o boot simply imprimia um banner e
//   seguia. Um dispositivo que reiniciou 500 vezes por brownout e um
//   dispositivo que reiniciou 500 vezes por travamento de software
//   eram INDISTINGUEIS no log.
//
// ESTADO QUE ESTE MODULO MANTEM
//   - `boots`: total de inicializacoes.
//   - `brownouts`: reinicios por queda de alimentacao.
//   - `wdtResets`: reinicios por watchdog (travamento do loop).
//   - `swResets`: reinicios por software (ESP.restart()).
//   - `panics`: reinicios por panic/execucao (erro de software).
//   - `powerOn`: reinicios por ligamento.
//
// POR QUE O MODULO E' SEPARADO DO FIRMWARE
//   O firmware depende do ESP-IDF (esp_reset_reason(), esp_task_wdt_*).
//   Este modulo e' C++ puro: a CLASSIFICACAO da causa e' a parte que
//   tem aresta (panic != wdt != brownout != sw) e pode ser testada no
//   host, onde nao existe hardware.
//
// PERSISTENCIA E DESGASTE DE FLASH
//   Cada boot grava um contador na NVS. Numa operacao normal isso e'
//   irrelevante (um boot por mes, por exemplo). Mas num laco de
//   brownout — a alimentacao oscila e o dispositivo reinicia 50 vezes
//   por hora — a NVS suffers 50 escritas/hora, 438 mil por ano. Isso
//   consome a vida util da particao.
//
//   Por isso o modulo implementa um guarda de desgaste
//   (`shouldPersistNow`): a gravacao imediata so acontece quando a
//   CAUSA MUDOU (um brownout depois de um boot normal e' evento novo e
//   relevante) ou quando passaram `persistEveryBoots` boots. O resto
//   fica acumulado em RAM e e' gravado no flush periodico. O contador
//   exato de brownouts pode ficar alguns boots atras no pior caso; a
//   CAUSA do ultimo reinicio (que e' o que importa para o operador) e'
//   sempre exata e visivel imediatamente.
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST
// (tests/reset_tracker.cpp).
#ifndef HEF_RESET_TRACKER_H
#define HEF_RESET_TRACKER_H

#include <stdint.h>
#include <string.h>

// ---------------------------------------------------------------------
// Causa de reinicio (espelho de esp_reset_reason_t do ESP-IDF)
// ---------------------------------------------------------------------
// Os valores ESP correspondem EXATAMENTE a esp_reset_reason_t do
// ESP-IDF, para que a conversao seja um simples cast. O nome e' o que
// o operador ve no console e na API.
enum HefResetReason {
    HEF_RST_UNKNOWN     = 0,   // ESP_RST_UNKNOWN
    HEF_RST_POWERON     = 1,   // ESP_RST_POWERON
    HEF_RST_EXT         = 2,   // ESP_RST_EXT
    HEF_RST_SW          = 3,   // ESP_RST_SW
    HEF_RST_PANIC       = 4,   // ESP_RST_PANIC
    HEF_RST_INT_WDT     = 5,   // ESP_RST_INT_WDT
    HEF_RST_TASK_WDT    = 6,   // ESP_RST_TASK_WDT
    HEF_RST_WDT         = 7,   // ESP_RST_WDT
    HEF_RST_DEEPSLEEP   = 8,   // ESP_RST_DEEPSLEEP
    HEF_RST_BROWNOUT    = 9,   // ESP_RST_BROWNOUT
    HEF_RST_SDIO        = 10   // ESP_RST_SDIO
};

// Nome curto da causa (portugues, sem acentos, para console/JSON).
inline const char* hefResetReasonName(uint8_t reason) {
    switch (reason) {
        case HEF_RST_UNKNOWN:   return "desconhecida";
        case HEF_RST_POWERON:   return "ligamento";
        case HEF_RST_EXT:       return "pino externo";
        case HEF_RST_SW:        return "software";
        case HEF_RST_PANIC:     return "panic";
        case HEF_RST_INT_WDT:   return "wdt-interrupcao";
        case HEF_RST_TASK_WDT:  return "wdt-tarefa";
        case HEF_RST_WDT:       return "wdt";
        case HEF_RST_BROWNOUT:  return "brownout";
        case HEF_RST_DEEPSLEEP: return "deep-sleep";
        case HEF_RST_SDIO:      return "sdio";
        default:                return "invalida";
    }
}

// A causa e' um travamento (bug de software)?
inline bool hefResetIsFault(uint8_t reason) {
    return reason == HEF_RST_PANIC ||
           reason == HEF_RST_INT_WDT ||
           reason == HEF_RST_TASK_WDT ||
           reason == HEF_RST_WDT;
}

// A causa e' uma queda de energia?
inline bool hefResetIsBrownout(uint8_t reason) {
    return reason == HEF_RST_BROWNOUT;
}

// ---------------------------------------------------------------------
// Contadores de operacao
// ---------------------------------------------------------------------
struct HefResetCounters {
    uint32_t boots;         // total de inicializacoes
    uint32_t brownouts;     // reinicios por queda de alimentacao
    uint32_t wdtResets;     // reinicios por watchdog
    uint32_t swResets;      // reinicios por software (ESP.restart())
    uint32_t panics;        // reinicios por panic (erro de software)
    uint32_t powerOn;       // reinicios por ligamento
    uint8_t  lastReason;    // causa do ULTIMO boot
    uint8_t  lastPersisted; // causa gravada por ultimo na NVS
};

// Versao do formato serializado. Se mudar, o formato e' invalidado
// (e os contadores zeram) — melhor do que interpretar bytes velhos
// com semantica nova.
#define HEF_RESET_FORMAT_VERSION 1

// Tamanho serializado (little-endian, sem padding: 28 bytes).
#define HEF_RESET_BLOB_LEN 28

// ---------------------------------------------------------------------
// HefResetTracker
// ---------------------------------------------------------------------
class HefResetTracker {
private:
    HefResetCounters c_;
    uint32_t bootsSincePersist_;   // boots desde a ultima gravacao
    bool     dirty_;                // ha contador nao gravado?

public:
    HefResetTracker()
        : bootsSincePersist_(0), dirty_(false) {
        memset(&c_, 0, sizeof(c_));
        c_.lastReason    = HEF_RST_UNKNOWN;
        c_.lastPersisted = HEF_RST_UNKNOWN;
    }

    // -------------------------------------------------------------
    // begin: registra o boot atual.
    //
    // `reason` = esp_reset_reason() do boot atual.
    // `persistEveryBoots` = quantos boots podem acontecer sem gravar
    //                        (guarda de desgaste da NVS).
    // Retorna true se o estado ficou "sujo" (ha algo a gravar).
    // -------------------------------------------------------------
    bool begin(uint8_t reason, uint32_t persistEveryBoots) {
        c_.boots++;

        // A causa do boot anterior e' a que intercessa: e' ela que
        // explica POR QUE este boot aconteceu.
        uint8_t prev = c_.lastReason;

        switch (reason) {
            case HEF_RST_BROWNOUT: c_.brownouts++; break;
            case HEF_RST_TASK_WDT:
            case HEF_RST_INT_WDT:
            case HEF_RST_WDT:      c_.wdtResets++; break;
            case HEF_RST_SW:
            case HEF_RST_DEEPSLEEP: c_.swResets++; break;
            case HEF_RST_PANIC:    c_.panics++;    break;
            case HEF_RST_POWERON:  c_.powerOn++;   break;
            default: break;   // UNKNOWN / EXT / SDIO: so contam em 'boots'
        }

        c_.lastReason = reason;
        bootsSincePersist_++;
        dirty_ = true;

        // Guarda de desgaste: grava AGORA se a causa MUDOU (evento
        // novo e relevante para o operador) ou se ja passou o numero
        // de boots configurado.
        bool causeChanged = (prev != reason);
        if (causeChanged || persistEveryBoots == 0 ||
            bootsSincePersist_ >= persistEveryBoots) {
            return true;    // o chamador deve gravar
        }
        return false;
    }

    // -------------------------------------------------------------
    // shouldPersistNow: o estado deve ser gravado agora?
    // (chamado pelo flush periodico e antes de um reinicio)
    // -------------------------------------------------------------
    bool shouldPersistNow() const { return dirty_; }

    // Marca o estado como gravado (apos uma escrita bem-sucedida).
    void markPersisted() {
        dirty_ = false;
        bootsSincePersist_ = 0;
        c_.lastPersisted = c_.lastReason;
    }

    const HefResetCounters& counters() const { return c_; }

    uint8_t lastReason() const { return c_.lastReason; }
    uint32_t boots() const { return c_.boots; }

    // -------------------------------------------------------------
    // Serializacao (little-endian, 28 bytes, sem padding)
    // -------------------------------------------------------------
    void exportBlob(uint8_t* out, size_t len) const {
        if (!out || len < HEF_RESET_BLOB_LEN) return;
        memset(out, 0, HEF_RESET_BLOB_LEN);
        out[0] = HEF_RESET_FORMAT_VERSION;
        out[1] = c_.lastReason;
        out[2] = c_.lastPersisted;
        out[3] = 0;   // reservado
        put32(out + 4,  c_.boots);
        put32(out + 8,  c_.brownouts);
        put32(out + 12, c_.wdtResets);
        put32(out + 16, c_.swResets);
        put32(out + 20, c_.panics);
        put32(out + 24, c_.powerOn);
    }

    // Importa um blob. Retorna false se o blob for invalido (versao
    // desconhecida, tamanho errado ou contadores inconsistentes) —
    // nesse caso os contadores sao ZERADOS (fail-safe: melhor perder
    // contadores do que aceitar bytes com semantica desconhecida).
    bool importBlob(const uint8_t* in, size_t len) {
        memset(&c_, 0, sizeof(c_));
        bootsSincePersist_ = 0;
        dirty_ = false;
        c_.lastReason    = HEF_RST_UNKNOWN;
        c_.lastPersisted = HEF_RST_UNKNOWN;
        if (!in || len < HEF_RESET_BLOB_LEN) return false;
        if (in[0] != HEF_RESET_FORMAT_VERSION) return false;

        c_.lastReason    = in[1];
        c_.lastPersisted = in[2];
        c_.boots      = get32(in + 4);
        c_.brownouts  = get32(in + 8);
        c_.wdtResets  = get32(in + 12);
        c_.swResets   = get32(in + 16);
        c_.panics     = get32(in + 20);
        c_.powerOn    = get32(in + 24);

        // Um blob corrompido nao pode deixar os contadores em valores
        // absurdos: sanity check. Um contador acima de 100 milhoes de
        // boots significa que o blob esta corrompido (ou que a NVS foi
        // zerada e o espaco foi lido como lixo). Um contador de uma
        // classe maior que o total de boots e' logicamente impossivel.
        bool invalido =
            (c_.boots     > 100000000UL) ||
            (c_.brownouts > c_.boots) ||
            (c_.wdtResets > c_.boots) ||
            (c_.swResets  > c_.boots) ||
            (c_.panics    > c_.boots) ||
            (c_.powerOn   > c_.boots);

        if (invalido) {
            // ZERA os contadores: um blob recusado nao pode deixar
            // valores pela metade na memoria (o caller mostraria
            // numeros absurdos no console).
            memset(&c_, 0, sizeof(c_));
            c_.lastReason    = HEF_RST_UNKNOWN;
            c_.lastPersisted = HEF_RST_UNKNOWN;
            return false;
        }
        return true;
    }

private:
    static void put32(uint8_t* p, uint32_t v) {
        p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
    }
    static uint32_t get32(const uint8_t* p) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
    }
};

// ---------------------------------------------------------------------
// Reinicio controlado
// ---------------------------------------------------------------------
// Um `ESP.restart()` sem registro e' um reinicio cego: o operador ve
// "reiniciou" e nao sabe se foi ele, o watchdog, ou a falta de
// energia. Este registro marca a intencao ANTES do reinicio, para que
// o proximo boot possa distinguir "alguem pediu" de "algo travou".
//
// O registro e' escrito na NVS (nao no vault cifrado): nao e' segredo,
// e o vault e' reescrito inteiro a cada gravacao — caro demais para
// um contador.
//
// A "intencao" e' gravada com um numero de sequence proprio, para que
// um reinicio happening no instante exato da gravacao nao se confunda
// com o boot seguinte.
#define HEF_RESET_INTENT_NONE  0
#define HEF_RESET_INTENT_USER  1   // operador pediu (comando de console)
#define HEF_RESET_INTENT_FAULT 2   // falha automatica (heap critico, etc)

struct HefResetIntent {
    uint8_t  kind;      // HEF_RESET_INTENT_*
    uint8_t  reason;    // causa registrada (para faults)
    uint32_t sequence;  // numero de sequence do pedido
};

// ---------------------------------------------------------------------
// hefResetIntentMatches
//
// O intent gravado antes do reinicio corresponde a ESTE boot?
//
// `sequence` e' o numero do boot que o reinicio produziria. Apos
// `begin()`, `counters().boots` e' exatamente esse numero. Um intent
// com outra sequence e' de um reinicio mais antigo (ou foi gravado por
// um boot que nao chegou a acontecer) e NAO deve ser reportado.
//
// Sem essa checagem, um `reboot` do operador deixaria um intent
// "pendente" que continuaria aparecendo em todos os boots seguintes —
// dizendo "reinicio solicitado pelo operador" em reinícios que foram
// travamentos. A informacao errada e' pior do que a ausencia dela.
// ---------------------------------------------------------------------
inline bool hefResetIntentMatches(const HefResetIntent& intent,
                                  uint32_t boots) {
    if (intent.kind == HEF_RESET_INTENT_NONE) return false;
    if (intent.kind != HEF_RESET_INTENT_USER &&
        intent.kind != HEF_RESET_INTENT_FAULT) return false;
    return intent.sequence == boots;
}

// Nome legivel da intencao do reinicio.
inline const char* hefResetIntentName(uint8_t kind) {
    switch (kind) {
        case HEF_RESET_INTENT_USER: return "solicitado pelo operador";
        case HEF_RESET_INTENT_FAULT: return "falha automatica";
        default:                     return "desconhecida";
    }
}

#endif // HEF_RESET_TRACKER_H
