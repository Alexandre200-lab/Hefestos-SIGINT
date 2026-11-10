// watchdog.h - Watchdog de tarefa (ligacao com o ESP-IDF) - v5.1.0
//
// Este arquivo isola a chamada ao ESP-IDF. A DECISAO (qual timeout
// ficou em vigor, quando alimentar) esta em `watchdog_policy.h`, que
// e' puro e testado no host.
//
// COMPATIBILIDADE
//   A assinatura de `esp_task_wdt_init()` mudou entre o IDF 4.4 (core
//   Arduino-ESP32 2.0.17, congelado ate a Fase 4 do plano) e o IDF 5.x
//   (core 3.x). O versionamento abaixo mantem este arquivo compilando
//   nos dois.
#ifndef HEF_WATCHDOG_H
#define HEF_WATCHDOG_H

#include <stdint.h>
#include <Arduino.h>
#include <esp_task_wdt.h>

#include <hefestos_pins.h>
#include <watchdog_policy.h>

// ---------------------------------------------------------------------
// Configuracao
// ---------------------------------------------------------------------
// Timeout do watchdog, em segundos. O plano pede 30 s; o valor real
// pode ser MENOR se outro componente ja tiver inicializado o TWDT (o
// que e' melhor: deteccao mais rapida).
#ifndef HEF_WDT_TIMEOUT_S
#define HEF_WDT_TIMEOUT_S 30
#endif

// Quantas alimentacoes por janela de timeout nas operacoes longas.
#ifndef HEF_WDT_FEED_DIVISOR
#define HEF_WDT_FEED_DIVISOR 3
#endif

// ---------------------------------------------------------------------
// Estado global
// ---------------------------------------------------------------------
// Funcao com estatico local: em C++11 (o padrao do core 2.0.17) nao
// existem "inline variables", mas uma funcao `inline` com estatico
// local tem uma unica instancia em todo o programa.
inline HefWatchdogState& hefWdtState() {
    static HefWatchdogState s = { false, false, 0, 0 };
    return s;
}

inline HefProgressGuard& hefWdtProgress() {
    static HefProgressGuard g;
    return g;
}

// ---------------------------------------------------------------------
// hefWatchdogInit
//
// Inicializa o TWDT e inscreve a task do loop.
//
// O core Arduino-ESP32 2.0.17 alimenta o WDT ANTES de cada `loop()`
// (via `loopTaskWDTEnabled`), o que significa que um `loop()` que
// trave por mais que o timeout NAO e' alimentado e o TWDT dispara.
//
// Retorna o estado resolvido (ver `hefWatchdogResolve`).
// ---------------------------------------------------------------------
inline HefWatchdogState hefWatchdogInit() {
    // --- 1) Inicializa o TWDT ---
    // O codigo de erro e' repassado EXATAMENTE como veio do IDF. Nao
    // pode ser colapsado num unico valor: um erro de memoria
    // (0x101) classificado como "ja inicializado" (0x103) faria o
    // operador acreditar que existe protecao que nao existe.
    int initErr = HEF_WDT_ERR_OK;
#if defined(ESP_IDF_VERSION_MAJOR) && (ESP_IDF_VERSION_MAJOR >= 5)
    // IDF 5.x: a API exige uma struct de configuracao.
    {
        esp_task_wdt_config_t cfg = {};
        cfg.timeout_ms = (uint32_t)HEF_WDT_TIMEOUT_S * 1000UL;
        cfg.panic = true;
        cfg.idle_core_mask = 0;
        initErr = (int)esp_task_wdt_init(&cfg);
    }
#else
    // IDF 4.4 (core 2.0.17): a API e' (timeout_s, panic).
    initErr = (int)esp_task_wdt_init((uint32_t)HEF_WDT_TIMEOUT_S, true);
#endif

    // --- 2) Inscreve a task do loop ---
    // `enableLoopWDT()` usa o handle global `loopTaskHandle` do core e
    // liga `loopTaskWDTEnabled` (o core passa a alimentar o WDT antes
    // de cada `loop()`).
    //
    // A inscricao e' tentada MESMO quando a init devolveu INVALID_STATE:
    // nesse caso o TWDT ja existe e a inscricao ainda pode funcionar.
    // Sem a inscricao, nao ha watchdog sobre o loop, por mais que o
    // TWDT exista.
    bool subscribed = false;
    if (initErr == HEF_WDT_ERR_OK ||
        initErr == HEF_WDT_ERR_INVALID_STATE) {
        enableLoopWDT();
        subscribed = (esp_task_wdt_status(NULL) == ESP_OK);
    }

    // --- 3) Resolve o estado ---
    // No IDF 4.4 nao ha API de leitura do timeout em vigor; quando o
    // TWDT ja existia e a init nao o alterou, o timeout e' reportado
    // como 0 (desconhecido) em vez de mentir dizendo que e' o pedido.
    uint32_t existingS = 0;
    hefWdtState() = hefWatchdogResolve(initErr, subscribed,
                                        (uint32_t)HEF_WDT_TIMEOUT_S, existingS);
    return hefWdtState();
}

inline bool     hefWatchdogActive()   { return hefWdtState().active; }
inline uint32_t hefWatchdogTimeoutS() { return hefWdtState().timeoutS; }

// ---------------------------------------------------------------------
// hefWatchdogFeed
//
// Alimenta o watchdog da task corrente. Chamar dentro de operacoes
// longas que AVANCARAM (ver a nota sobre mascaramento em
// `watchdog_policy.h`).
inline void hefWatchdogFeed() {
    if (!hefWdtState().active) return;
    feedLoopWDT();
}

// ---------------------------------------------------------------------
// Operacoes longas
// ---------------------------------------------------------------------
// Inicia o acompanhamento de uma operacao longa. `timeoutS` e' o
// timeout efetivo do WDT (0 = desconhecido).
inline void hefWatchdogBeginLongOp(uint32_t timeoutS) {
    hefWdtProgress().configure(timeoutS, HEF_WDT_FEED_DIVISOR);
    hefWdtProgress().markFed((uint32_t)millis());
}

// Deve alimentar o WDT agora? Se sim, alimenta e devolve `true` — o
// chamador decide se registra o progresso no log.
inline bool hefWatchdogLongOpStep(uint32_t nowMs) {
    if (!hefWdtState().active) return false;
    if (!hefWdtProgress().due(nowMs)) return false;
    hefWdtProgress().markFed(nowMs);
    feedLoopWDT();
    return true;
}

#endif // HEF_WATCHDOG_H
