// =====================================================================
// tests/watchdog_policy.cpp
//
// Teste de unidade da politica do watchdog (item 1.4 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/watchdog_policy.cpp -o /tmp/hef_wdt_test
//
// FALHA COBERTA
//   A v5.0.0 nao tinha watchdog proprio: um travamento do loop
//   principal nao era detectado e o dispositivo ficava "vivo" mas
//   inutil. O plano exige `esp_task_wdt_init(30s)` com reinicio em
//   menos de 30 s e causa WDT visivel.
//
//   Este teste cobre a PARTE DECISIVA (que fica em
//   `watchdog_policy.h`, puro e testavel no host):
//     - a resolucao do estado do watchdog a partir do resultado da
//       init (OK / ja-inicializado / falha real);
//     - a honestidade do timeout reportado (nunca mentir);
//     - o calculo do intervalo de alimentacao das operacoes longas,
//       com a garantia de alimentacao dentro da janela do WDT.
//
// Roda no HOST (g++), sem hardware.
// =====================================================================
#include <cstdio>
#include <cstdint>

#include "framework.h"
#include "watchdog_policy.h"

// ---------------------------------------------------------------------
// 1) Resolucao do estado apos a init
// ---------------------------------------------------------------------
static void testInitResolution() {
    SECTION("Watchdog - resolucao da init");

    // Caso normal: a init funcionou e a task foi inscrita.
    HefWatchdogState st = hefWatchdogResolve(HEF_WDT_ERR_OK, true, 30, 0);
    CHECK(st.active, "watchdog ativo apos init bem-sucedida");
    CHECK(!st.preInitialized, "nao foi pre-inicializado");
    CHECK(st.timeoutS == 30, "timeout em vigor e' o pedido (30 s)");
    CHECK(st.initErr == HEF_WDT_ERR_OK, "sem erro");

    // A init funcionou mas a inscricao falhou: NAO ha watchdog.
    // Um watchdog que nao inscreveu a task nao protege nada.
    st = hefWatchdogResolve(HEF_WDT_ERR_OK, false, 30, 0);
    CHECK(!st.active, "sem inscricao, o watchdog esta inativo");
    CHECK(st.initErr == HEF_WDT_ERR_OK, "a init em si nao falhou");

    // O TWDT ja existia (bootloader): a inscricao pode funcionar, mas o
    // timeout em vigor NAO e' o pedido — e o IDF 4.4 nao permite
    // le-lo. Reportar 30 s aqui seria MENTIR.
    st = hefWatchdogResolve(HEF_WDT_ERR_INVALID_STATE, true, 30, 0);
    CHECK(st.active, "watchdog ativo com TWDT pre-existente");
    CHECK(st.preInitialized, "marcado como pre-inicializado");
    CHECK(st.timeoutS == 0, "timeout desconhecido e' reportado como 0");
    CHECK(st.initErr == HEF_WDT_ERR_INVALID_STATE, "erro preservado");

    // Se o timeout pre-existente for conhecido, ele e' reportado.
    st = hefWatchdogResolve(HEF_WDT_ERR_INVALID_STATE, true, 30, 5);
    CHECK(st.timeoutS == 5, "timeout pre-existente conhecido e' reportado");

    // Falha real de init: SEM watchdog. O caller precisa reportar.
    st = hefWatchdogResolve(HEF_WDT_ERR_NO_MEM, false, 30, 0);
    CHECK(!st.active, "falha de init deixa o watchdog inativo");
    CHECK(st.initErr == HEF_WDT_ERR_NO_MEM, "erro preservado");
    CHECK(!st.preInitialized, "falha de init nao e' pre-inicializacao");

    // --- REGRESSAO: os codigos do ESP-IDF nao sao negativos pequenos ---
    //
    // A v5.1.0 usava -1 para INVALID_STATE e -12 para NO_MEM. Os
    // codigos reais do esp_err.h sao 0x103 (259) e 0x101 (257).
    //
    // O efeito do erro era GRAVE: uma falha de memoria (257) era
    // classificada como "TWDT ja inicializado" (259) e o resolvedor
    // devolvia `active = subscribed` — ou seja, o operador via
    // "watchdog: ativo" num dispositivo SEM watchdog. A protecao
    // apareceria no console e na API sem existir.
    CHECK(HEF_WDT_ERR_INVALID_STATE == 0x103,
          "ESP_ERR_INVALID_STATE = 0x103 (259)");
    CHECK(HEF_WDT_ERR_NO_MEM == 0x101,
          "ESP_ERR_NO_MEM = 0x101 (257)");
    CHECK(HEF_WDT_ERR_INVALID_STATE != -1,
          "INVALID_STATE nao e' -1 (que e' ESP_FAIL)");
    CHECK(HEF_WDT_ERR_NO_MEM != -12,
          "NO_MEM nao e' -12 (que nao existe no esp_err.h)");

    // Regressao funcional: uma falha de memoria NAO pode ser
    // classificada como pre-inicializacao.
    st = hefWatchdogResolve(HEF_WDT_ERR_NO_MEM, true, 30, 0);
    CHECK(!st.active,
          "falha de memoria com inscricao ok NAO pode reportar watchdog ativo");
    CHECK(!st.preInitialized,
          "falha de memoria NAO e' pre-inicializacao");
    CHECK(st.timeoutS == 0, "falha de init nao reporta timeout");

    // E o inverso: um INVALID_STATE real continua sendo pre-init.
    st = hefWatchdogResolve(HEF_WDT_ERR_INVALID_STATE, true, 30, 0);
    CHECK(st.preInitialized, "INVALID_STATE real e' pre-inicializacao");
}

// ---------------------------------------------------------------------
// 2) O timeout pedido tem de ser respeitado
// ---------------------------------------------------------------------
static void testTimeoutBudget() {
    SECTION("Watchdog - orcamento de timeout");

    // O plano pede 30 s: o travamento do loop tem de derrubar o
    // dispositivo em MENOS de 30 s (o timeout e' o limite superior).
    HefWatchdogState st = hefWatchdogResolve(HEF_WDT_ERR_OK, true, 30, 0);
    CHECK(st.timeoutS > 0 && st.timeoutS <= 30,
          "o timeout em vigor respeita o limite de 30 s do plano");

    // Se o TWDT pre-existia com timeout MENOR (mais severo), tudo bem.
    st = hefWatchdogResolve(HEF_WDT_ERR_INVALID_STATE, true, 30, 5);
    CHECK(st.timeoutS == 5 && st.timeoutS <= 30,
          "timeout pre-existente mais severo e' aceito");

    // Um timeout pre-existente MAIOR que o pedido e' aceitavel, mas
    // deve ser reportado fielmente (o operador precisa saber).
    st = hefWatchdogResolve(HEF_WDT_ERR_INVALID_STATE, true, 30, 60);
    CHECK(st.timeoutS == 60, "timeout pre-existente maior e' reportado fielmente");
}

// ---------------------------------------------------------------------
// 3) Alimentacao das operacoes longas
// ---------------------------------------------------------------------
static void testProgressGuard() {
    SECTION("Watchdog - alimentacao de operacoes longas");

    HefProgressGuard g;

    // Timeout de 30 s, divisor 3: intervalo teorico de 10 s, com
    // margem de seguranca pela metade -> 5 s.
    g.configure(30, 3);
    CHECK(g.intervalMs() == 5000, "intervalo de alimentacao = 5 s");

    // A primeira alimentacao e' imediata (o `fed_` garante).
    CHECK(g.due(0), "a primeira alimentacao e' imediata");
    g.markFed(0);
    CHECK(!g.due(0), "logo apos alimentar, nao alimenta de novo");
    CHECK(!g.due(1000), "1 s depois: ainda nao");
    CHECK(!g.due(4999), "4,999 s depois: ainda nao");
    CHECK(g.due(5000), "5 s depois: alimenta");

    // A margem garante pelo menos `divisor` alimentacoes por janela.
    g.markFed(0);
    uint32_t alimentacoes = 0;
    for (uint32_t t = 0; t <= 30000; t += 100) {
        if (g.due(t)) { alimentacoes++; g.markFed(t); }
    }
    CHECK(alimentacoes >= 6, "pelo menos 6 alimentacoes em 30 s (divisor 3)");
    CHECK(alimentacoes <= 8, "nao alimenta em excesso");

    // Timeout desconhecido (0): assume o pior caso do plano.
    HefProgressGuard h;
    h.configure(0, 3);
    CHECK(h.intervalMs() == 5000, "timeout desconhecido assume 30 s");

    // Divisor zero: precisa ser corrigido para um valor seguro.
    HefProgressGuard i;
    i.configure(30, 0);
    CHECK(i.intervalMs() == 5000, "divisor zero e' corrigido para 3");

    // Timeout de 1 s (caso extremo): o intervalo nao pode ser zero.
    HefProgressGuard j;
    j.configure(1, 3);
    CHECK(j.intervalMs() >= 1, "intervalo nunca e' zero");

    // O relogio pode dar a volta (millis() com 32 bits): a subtracao
    // sem sinal precisa continuar funcionando.
    HefProgressGuard k;
    k.configure(30, 3);
    k.markFed(0xFFFFF000UL);
    CHECK(!k.due(0xFFFFF100UL), "logo apos a virada do relogio: nao alimenta");
    uint32_t wrapped = (uint32_t)(0xFFFFF000UL + 6000UL);
    CHECK(k.due(wrapped), "5 s depois da virada do relogio: alimenta");
}

// ---------------------------------------------------------------------
// 3-bis) INVARIANTE DE SEGURANCA: o intervalo cabe na janela do WDT
// ---------------------------------------------------------------------
// Se o intervalo de alimentacao fosse maior que a janela do WDT, uma
// operacao longa que avancasse lentamente dispararia um reinicio
// FALSO — o pior tipo de falha: o dispositivo reiniciando sozinho em
// campo, sem causa.
//
// O invariante e': `intervalMs * divisor <= timeout * 1000`. Com a
// margem de seguranca (metade do intervalo teorico), ha folga de 2x.
static void testIntervalFitsWindow() {
    SECTION("Watchdog - o intervalo cabe na janela do WDT");

    const uint32_t timeouts[] = { 1, 2, 5, 10, 30, 60, 120 };
    const uint32_t divisors[] = { 1, 2, 3, 4, 5, 10 };

    for (size_t t = 0; t < sizeof(timeouts) / sizeof(timeouts[0]); t++) {
        for (size_t d = 0; d < sizeof(divisors) / sizeof(divisors[0]); d++) {
            HefProgressGuard g;
            g.configure(timeouts[t], divisors[d]);
            uint32_t iv = g.intervalMs();
            CHECK(iv > 0, "o intervalo nunca e' zero");
            // O intervalo (com a margem de 2x) tem de caber na janela:
            // iv * divisor * 2 <= timeout * 1000.
            uint64_t consumo = (uint64_t)iv * divisors[d] * 2ULL;
            uint64_t janela  = (uint64_t)timeouts[t] * 1000ULL;
            CHECK(consumo <= janela,
                  "o intervalo cabe na janela do WDT (timeout x divisor)");
        }
    }
}

// ---------------------------------------------------------------------
// 4) O guarda e' uma CONSULTA, nao uma acao
// ---------------------------------------------------------------------
// `due()` nao alimenta nada: e' uma pergunta "o WDT precisa de
// alimentacao?". Quem alimenta e' o chamador, e so o faz depois de um
// AVANCO real da operacao.
//
// Consequencia de seguranca: um codigo que TRAVOU (deixou de avancar)
// para de chamar `due()`/`markFed()`, e o WDT expira normalmente. O
// travamento NAO e' mascarado. Este e' o requisito central do item
// 1.4: um dispositivo travado tem de REINICIAR, nao ficar "vivo" e
// inutil.
static void testGuardIsAQuery() {
    SECTION("Watchdog - o guarda e' uma consulta, nao uma acao");

    HefProgressGuard g;
    g.configure(30, 3);

    // A primeira consulta e' devida.
    CHECK(g.due(0), "a primeira consulta e' devida");

    // A consulta repetida sem `markFed()` continua devida — o guarda
    // nao se auto-alimenta. Quem decide alimentar e' o chamador, e ele
    // so chama `markFed()` depois de um avanco real.
    CHECK(g.due(0), "consultas repetidas continuam devidas");
    CHECK(g.due(0), "o guarda nao se auto-alimenta");

    // Apos um avanco (markFed), a consulta nao e' devida ate o
    // intervalo passar.
    g.markFed(0);
    CHECK(!g.due(0), "apos o avanco, a consulta nao e' devida");
    CHECK(!g.due(4999), "ainda dentro do intervalo");
    CHECK(g.due(5000), "passado o intervalo, a consulta e' devida");

    // O intervalo do guarda e' sempre positivo: um intervalo zero
    // causaria alimentacao em laco (desperdicio) ou, no outro extremo,
    // um intervalo enorme causaria reinicio falso.
    for (uint32_t timeout = 1; timeout <= 60; timeout++) {
        HefProgressGuard h;
        h.configure(timeout, 3);
        CHECK(h.intervalMs() > 0, "intervalo sempre positivo");
    }
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - politica do watchdog\n");
    printf("=====================================================\n");

    testInitResolution();
    testTimeoutBudget();
    testProgressGuard();
    testIntervalFitsWindow();
    testGuardIsAQuery();

    return heftest::summary("politica do watchdog");
}
