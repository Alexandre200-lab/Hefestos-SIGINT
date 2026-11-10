// watchdog_policy.h - Politica do watchdog (parte pura) - v5.1.0
//
// OBJETIVO
//   Item 1.4 do plano de escala: um travamento do loop principal
//   (deadlock, loop infinito, espera infinita) deve derrubar o
//   dispositivo em menos de 30 s, com a CAUSA visivel.
//
//   A v5.0.0 nao tinha watchdog proprio. O TWDT do IDF so vigiava a
//   task idle (e, no ESP32, a CPU0). Um travamento no `loop()` — que
//   e' onde vive praticamente toda a logica — nao era detectado: o
//   dispositivo ficava "vivo" mas inutil, com o HTTP respondendo nada
//   e o log forense parando de crescer.
//
// POR QUE ESTA PARTE E' SEPARADA
//   A ligacao com o ESP-IDF (`esp_task_wdt_*`) fica em `watchdog.h`.
//   Aqui fica a DECISAO — que timeout ficou em vigor, se o watchdog
//   esta ativo, e quando uma operacao longa deve alimentar o WDT —
//   que e' a parte com aresta e pode ser testada no host.
//
// ALIMENTACAO DE OPERACOES LONGAS
//   Uma operacao longa (exportacao do log forense, gravacao no SD,
//   sweep do espectro) que bloqueie por mais que o timeout dispararia
//   um reinicio INESPERADO. A solucao e' alimentar o WDT durante a
//   operacao.
//
//   ATENCAO: alimentar o WDT dentro de uma operacao que TRAVOU de
//   verdade (por exemplo, um SD que nunca responde) e' perigoso: o
//   WDT nunca dispara e o travamento fica mascarado. Por isso o
//   progresso so e' reportado em pontos onde a operacao realmente
//   AVANCOU (um registro gravado, um ponto do sweep varrido). Se a
//   operacao travar no meio, o WDT expira normalmente.
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST
// (tests/watchdog_policy.cpp).
#ifndef HEF_WATCHDOG_POLICY_H
#define HEF_WATCHDOG_POLICY_H

#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------
// Estado do watchdog
// ---------------------------------------------------------------------
struct HefWatchdogState {
    bool     active;         // a task do loop esta inscrita no TWDT?
    bool     preInitialized; // o TWDT ja estava inicializado por outro
                             // componente (bootloader)? Entao o timeout
                             // em vigor NAO e' o que pedimos.
    uint32_t timeoutS;       // timeout efetivo em segundos (0 = desconhecido)
    int      initErr;        // codigo de erro da init (0 = OK)
};

// Erros do ESP-IDF que interessam (esp_err_t). Repetidos aqui para
// que o modulo puro nao dependa do IDF.
//
// ATENCAO: os codigos do ESP-IDF NAO sao negativos pequenos. Sao
// valores do tipo 0x1xx (esp_err.h):
//   ESP_OK                 = 0
//   ESP_FAIL               = -1
//   ESP_ERR_NO_MEM         = 0x101 (257)
//   ESP_ERR_INVALID_ARG    = 0x102 (258)
//   ESP_ERR_INVALID_STATE  = 0x103 (259)
//
// A v5.1.0 usava -1 e -12, o que faria o resolvedor classificar uma
// falha de MEMORIA como "TWDT pre-inicializado" — e o operador
// acreditaria que existe protecao que nao existe.
#define HEF_WDT_ERR_OK              0
#define HEF_WDT_ERR_FAIL           (-1)
#define HEF_WDT_ERR_NO_MEM         0x101
#define HEF_WDT_ERR_INVALID_ARG    0x102
#define HEF_WDT_ERR_INVALID_STATE  0x103

// ---------------------------------------------------------------------
// hefWatchdogResolve
//
// Decide o estado do watchdog a partir do resultado da inicializacao.
//
// `initErr`      = retorno de esp_task_wdt_init()
// `subscribed`   = a inscricao da task do loop teve sucesso?
// `requestedS`   = timeout pedido (segundos)
// `existingS`    = timeout ja em vigor, se conhecido (0 = desconhecido)
//
// REGRAS
//   - init OK             -> ativo, timeout = requestedS.
//                            (No IDF 4.4 a documentacao do esp_task_wdt_init()
//                            diz que, se o TWDT ja existir, a chamada ATUALIZA
//                            o timeout; nesse caso o timeout em vigor e'
//                            mesmo o pedido. Se a implementacao real
//                            devolver INVALID_STATE, o proximo caso se
//                            aplica. Nos dois casos o reported e' honesto.)
//   - INVALID_STATE       -> o TWDT ja existia (bootloader/outro
//                            componente) e a chamada nao alterou o
//                            timeout. A inscricao ainda pode funcionar.
//                            O timeout e' desconhecido (o IDF 4.4 nao
//                            expoe leitura do timeout), e por isso e'
//                            reportado como 0 — o operador nao pode
//                            ficar com a impressao falsa de que o
//                            timeout e' o pedido.
//   - qualquer outro erro -> INATIVO. O caller DEVE reportar isso:
//                            um watchdog que nao inicializou e' pior
//                            que nenhum, porque o operador pode
//                            acreditar que existe protecao.
inline HefWatchdogState hefWatchdogResolve(int initErr, bool subscribed,
                                           uint32_t requestedS,
                                           uint32_t existingS) {
    HefWatchdogState st;
    st.active         = false;
    st.preInitialized = false;
    st.timeoutS       = 0;
    st.initErr        = initErr;

    if (initErr == HEF_WDT_ERR_OK) {
        st.active         = subscribed;
        st.timeoutS       = requestedS;
        st.preInitialized = false;
        return st;
    }

    if (initErr == HEF_WDT_ERR_INVALID_STATE) {
        // Ja havia um TWDT. A inscricao da task ainda pode ser feita.
        st.active         = subscribed;
        st.preInitialized = true;
        st.timeoutS       = existingS;   // 0 se desconhecido
        return st;
    }

    // Falha real de inicializacao: sem watchdog.
    st.active = false;
    return st;
}

// ---------------------------------------------------------------------
// HefProgressGuard
//
// Decide quando uma operacao longa deve alimentar o watchdog.
//
// REGRA
//   Alimentar pelo menos `feedDivisor` vezes dentro de cada janela de
//   timeout. Com divisor 3, uma operacao que avance slowly ainda
//   alimenta o WDT 3 vezes por timeout — sobra para 2 atrasos.
//
//   Se o intervalo calculado for 0 (timeout 0 = desconhecido), usa-se
//   um valor conservador: nao alimentar nunca e' perigoso (reinicio
//   falso), mas alimentar sempre e' desperdicio. Com timeout
//   desconhecido, o padrao e' 1 s.
//
// MARGEM DE SEGURANCA
//   O intervalo efetivo e' `timeout * 1000 / divisor` multiplicado por
//   1/2 (ou seja, metade do intervalo teorico). Isso garante que
//   mesmo com atraso de agendamento, ainda restam alimentacoes dentro
//   da janela do WDT.
class HefProgressGuard {
private:
    uint32_t intervalMs_;
    uint32_t lastFeedMs_;
    bool     fed_;

public:
    HefProgressGuard()
        : intervalMs_(1000), lastFeedMs_(0), fed_(false) {}

    // `timeoutS` = timeout efetivo do WDT (0 = desconhecido).
    // `divisor`  = quantas alimentacoes por janela de timeout.
    void configure(uint32_t timeoutS, uint32_t divisor) {
        if (divisor == 0) divisor = 3;
        uint32_t t = timeoutS;
        if (t == 0) {
            // Timeout desconhecido: assume-se o pior caso do plano
            // (30 s) para nao alimentar DEMAIS, e 1 s para nao
            // demorar demais.
            t = 30;
        }
        uint32_t iv = (t * 1000UL) / divisor;
        if (iv == 0) iv = 1;
        // Metade do intervalo teorico: margem para atraso de
        // agendamento.
        intervalMs_ = iv / 2;
        if (intervalMs_ == 0) intervalMs_ = 1;
        lastFeedMs_ = 0;
        fed_ = false;
    }

    uint32_t intervalMs() const { return intervalMs_; }

    // Deve alimentar agora? (NUNCA antes da primeira alimentacao:
    // `fed_` garante que a primeira chamada acontece de imediato.)
    bool due(uint32_t nowMs) {
        if (!fed_) return true;
        return (uint32_t)(nowMs - lastFeedMs_) >= intervalMs_;
    }

    void markFed(uint32_t nowMs) {
        lastFeedMs_ = nowMs;
        fed_ = true;
    }

    void reset() {
        lastFeedMs_ = 0;
        fed_ = false;
    }
};

#endif // HEF_WATCHDOG_POLICY_H
