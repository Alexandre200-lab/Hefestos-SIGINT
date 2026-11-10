// =====================================================================
// tests/reset_tracker.cpp
//
// Teste de unidade da causa de reinicio e dos contadores de operacao
// (item 1.4 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/reset_tracker.cpp -o /tmp/hef_reset_test
//
// FALHA COBERTA
//   A v5.0.0 nao registrava NADA do motivo do reinicio. Um dispositivo
//   que reiniciou 500 vezes por brownout (queda de alimentacao) e um
//   dispositivo que reiniciou 500 vezes por travamento de software
//   eram INDISTINGUEIS no log: o mesmo banner de boot, nada mais.
//
//   Este teste cobre:
//     - a classificacao de cada causa de reinicio do ESP-IDF;
//     - os contadores por classe (brownout, wdt, sw, panic, power-on);
//     - a serializacao/deserializacao do estado (round-trip);
//     - o saneamento de um blob corrompido (fail-safe);
//     - a guarda de desgaste da NVS (gravar nem sempre);
//     - a deteccao de mudanca de causa.
//
// Roda no HOST (g++), sem hardware.
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "framework.h"
#include "reset_tracker.h"

// ---------------------------------------------------------------------
// 1) Classificacao das causas
// ---------------------------------------------------------------------
static void testReasonClassification() {
    SECTION("Causa de reinicio - classificacao");

    // Cada causa do ESP-IDF tem um nome proprio.
    CHECK(strcmp(hefResetReasonName(HEF_RST_POWERON), "ligamento") == 0,
          "POWERON -> ligamento");
    CHECK(strcmp(hefResetReasonName(HEF_RST_SW), "software") == 0,
          "SW -> software");
    CHECK(strcmp(hefResetReasonName(HEF_RST_PANIC), "panic") == 0,
          "PANIC -> panic");
    CHECK(strcmp(hefResetReasonName(HEF_RST_TASK_WDT), "wdt-tarefa") == 0,
          "TASK_WDT -> wdt-tarefa");
    CHECK(strcmp(hefResetReasonName(HEF_RST_BROWNOUT), "brownout") == 0,
          "BROWNOUT -> brownout");
    CHECK(strcmp(hefResetReasonName(HEF_RST_DEEPSLEEP), "deep-sleep") == 0,
          "DEEPSLEEP -> deep-sleep");
    CHECK(strcmp(hefResetReasonName(200), "invalida") == 0,
          "causa fora da faixa -> invalida");

    // Nenhum nome pode ser vazio (o console imprimiria nada).
    for (int r = 0; r <= 10; r++) {
        CHECK(strlen(hefResetReasonName((uint8_t)r)) > 0,
              "toda causa tem nome nao vazio");
    }

    // Falha de software (precisa de depuracao).
    CHECK(hefResetIsFault(HEF_RST_PANIC), "panic e' falha");
    CHECK(hefResetIsFault(HEF_RST_TASK_WDT), "wdt de tarefa e' falha");
    CHECK(hefResetIsFault(HEF_RST_INT_WDT), "wdt de interrupcao e' falha");
    CHECK(hefResetIsFault(HEF_RST_WDT), "wdt generico e' falha");

    // Nao e' falha de software.
    CHECK(!hefResetIsFault(HEF_RST_POWERON), "ligamento nao e' falha");
    CHECK(!hefResetIsFault(HEF_RST_SW), "reinicio de software nao e' falha");
    CHECK(!hefResetIsFault(HEF_RST_BROWNOUT), "brownout nao e' falha de software");

    // Brownout: problema de energia, nao de software.
    CHECK(hefResetIsBrownout(HEF_RST_BROWNOUT), "brownout e' queda de energia");
    CHECK(!hefResetIsBrownout(HEF_RST_TASK_WDT),
          "wdt nao e' brownout (sao causas diferentes)");
    CHECK(!hefResetIsBrownout(HEF_RST_POWERON), "ligamento nao e' brownout");
}

// ---------------------------------------------------------------------
// 2) Contadores por classe
// ---------------------------------------------------------------------
static void testCounters() {
    SECTION("Causa de reinicio - contadores");

    HefResetTracker t;

    // Primeiro boot: ligamento.
    t.begin(HEF_RST_POWERON, 1);
    CHECK(t.counters().boots == 1, "1 boot contabilizado");
    CHECK(t.counters().powerOn == 1, "1 ligamento contabilizado");
    CHECK(t.counters().brownouts == 0, "nenhum brownout");
    CHECK(t.counters().wdtResets == 0, "nenhum wdt");
    CHECK(t.counters().swResets == 0, "nenhum sw");
    CHECK(t.counters().panics == 0, "nenhuma panic");

    // Brownout.
    t.begin(HEF_RST_BROWNOUT, 1);
    CHECK(t.counters().boots == 2, "2 boots contabilizados");
    CHECK(t.counters().brownouts == 1, "1 brownout contabilizado");
    CHECK(t.counters().powerOn == 1, "o ligamento anterior permanece");

    // Watchdog de tarefa.
    t.begin(HEF_RST_TASK_WDT, 1);
    CHECK(t.counters().wdtResets == 1, "1 wdt de tarefa contabilizado");

    // Watchdog de interrupcao e wdt generico tambem contam como wdt.
    t.begin(HEF_RST_INT_WDT, 1);
    t.begin(HEF_RST_WDT, 1);
    CHECK(t.counters().wdtResets == 3, "3 wdt contabilizados no total");

    // Reinicio de software (inclui deep sleep).
    t.begin(HEF_RST_SW, 1);
    t.begin(HEF_RST_DEEPSLEEP, 1);
    CHECK(t.counters().swResets == 2, "reinicios de software contabilizados");

    // Panic.
    t.begin(HEF_RST_PANIC, 1);
    CHECK(t.counters().panics == 1, "1 panic contabilizada");

    // Causa desconhecida: conta em 'boots' mas em nenhuma categoria.
    uint32_t bootsAntes = t.counters().boots;
    t.begin(HEF_RST_UNKNOWN, 1);
    CHECK(t.counters().boots == bootsAntes + 1,
          "causa desconhecida conta em boots");
    CHECK(t.counters().brownouts == 1 && t.counters().wdtResets == 3 &&
          t.counters().swResets == 2 && t.counters().panics == 1 &&
          t.counters().powerOn == 1,
          "causa desconhecida nao altera nenhuma categoria");

    // A ultima causa e' sempre a do boot atual.
    CHECK(t.lastReason() == HEF_RST_UNKNOWN, "ultima causa registrada");
}

// ---------------------------------------------------------------------
// 3) Serializacao: round-trip
// ---------------------------------------------------------------------
static void testSerialization() {
    SECTION("Causa de reinicio - serializacao");

    HefResetTracker t;
    t.begin(HEF_RST_POWERON, 1);
    t.begin(HEF_RST_BROWNOUT, 1);
    t.begin(HEF_RST_TASK_WDT, 1);
    t.markPersisted();

    uint8_t blob[HEF_RESET_BLOB_LEN];
    memset(blob, 0xAA, sizeof(blob));
    t.exportBlob(blob, sizeof(blob));

    CHECK(blob[0] == HEF_RESET_FORMAT_VERSION, "versao do formato gravada");
    CHECK(blob[1] == HEF_RST_TASK_WDT, "ultima causa gravada");

    // Round-trip: um tracker novo que importa o blob deve ter os
    // MESMOS contadores.
    HefResetTracker u;
    CHECK(u.importBlob(blob, sizeof(blob)), "blob valido importado");
    CHECK(u.counters().boots     == t.counters().boots, "boots preservados");
    CHECK(u.counters().brownouts == t.counters().brownouts, "brownouts preservados");
    CHECK(u.counters().wdtResets == t.counters().wdtResets, "wdt preservados");
    CHECK(u.counters().swResets  == t.counters().swResets, "sw preservados");
    CHECK(u.counters().panics    == t.counters().panics, "panics preservados");
    CHECK(u.counters().powerOn   == t.counters().powerOn, "powerOn preservados");
    CHECK(u.lastReason() == t.lastReason(), "ultima causa preservada");

    // O tracker importado NAO pode estar sujo (nada a gravar ainda).
    CHECK(!u.shouldPersistNow(), "tracker importado comeca limpo");
}

// ---------------------------------------------------------------------
// 4) Blob corrompido: fail-safe
// ---------------------------------------------------------------------
static void testCorruptBlob() {
    SECTION("Causa de reinicio - blob corrompido (fail-safe)");

    HefResetTracker t;
    t.begin(HEF_RST_POWERON, 1);
    t.begin(HEF_RST_BROWNOUT, 1);
    uint8_t blob[HEF_RESET_BLOB_LEN];
    t.exportBlob(blob, sizeof(blob));

    // Versao desconhecida: RECUSA (nao reinterpretar bytes velhos).
    HefResetTracker u;
    uint8_t bad[HEF_RESET_BLOB_LEN];
    memcpy(bad, blob, sizeof(bad));
    bad[0] = 0xFF;
    CHECK(!u.importBlob(bad, sizeof(bad)), "versao desconhecida e' recusada");
    CHECK(u.counters().boots == 0, "contadores ficam zerados apos recusa");

    // Blob curto: RECUSA.
    HefResetTracker v;
    CHECK(!v.importBlob(blob, HEF_RESET_BLOB_LEN - 1), "blob curto e' recusado");
    CHECK(v.counters().boots == 0, "contadores ficam zerados");

    // Blob nulo: RECUSA.
    HefResetTracker w;
    CHECK(!w.importBlob(nullptr, HEF_RESET_BLOB_LEN), "blob nulo e' recusado");

    // Contadores absurdos (bits invertidos): RECUSA.
    HefResetTracker x;
    uint8_t crazy[HEF_RESET_BLOB_LEN];
    memcpy(crazy, blob, sizeof(crazy));
    crazy[4] = 0xFF; crazy[5] = 0xFF; crazy[6] = 0xFF; crazy[7] = 0xFF;
    CHECK(!x.importBlob(crazy, sizeof(crazy)), "contador absurdo e' recusado");

    // Contador de brownout maior que o de boots: RECUSA.
    HefResetTracker y;
    uint8_t inconsistent[HEF_RESET_BLOB_LEN];
    memcpy(inconsistent, blob, sizeof(inconsistent));
    inconsistent[8] = 0xFF;   // brownouts = 255, boots = 2
    CHECK(!y.importBlob(inconsistent, sizeof(inconsistent)),
          "contadores inconsistentes sao recusados");
    CHECK(y.counters().brownouts == 0, "contadores ficam zerados");
}

// ---------------------------------------------------------------------
// 5) Guarda de desgaste da NVS
// ---------------------------------------------------------------------
static void testWearGuard() {
    SECTION("Causa de reinicio - guarda de desgaste da NVS");

    HefResetTracker t;

    // Boot 1: ligamento. A causa mudou (de desconhecida), entao grava.
    CHECK(t.begin(HEF_RST_POWERON, 10), "primeiro boot grava (causa mudou)");
    t.markPersisted();

    // Boots 2..10: a mesma causa. Nao deve gravar a cada boot.
    for (uint32_t i = 2; i <= 10; i++) {
        bool deveGravar = t.begin(HEF_RST_POWERON, 10);
        CHECK(!deveGravar, "boot repetido nao grava (guarda de desgaste)");
    }
    // Boot 11: completou a janela de 10 boots -> grava.
    bool deveGravar = t.begin(HEF_RST_POWERON, 10);
    CHECK(deveGravar, "a cada N boots o estado e' gravado");
    t.markPersisted();

    // Uma causa NOVA grava imediatamente, mesmo dentro da janela.
    CHECK(t.begin(HEF_RST_BROWNOUT, 10),
          "mudanca de causa grava imediatamente");
    t.markPersisted();
    CHECK(t.counters().brownouts == 1, "o brownout foi contabilizado");

    // Ja com a causa igual, nao grava ate completar a janela.
    CHECK(!t.begin(HEF_RST_BROWNOUT, 10),
          "brownout repetido nao grava dentro da janela");

    // O contador em RAM continua exato, mesmo sem gravar.
    CHECK(t.counters().brownouts == 2,
          "o contador em RAM e' exato mesmo sem gravacao");
    CHECK(t.counters().boots == 13, "total de boots exato em RAM");

    // O flush periodico grava o que estiver pendente.
    CHECK(t.shouldPersistNow(), "estado pendente e' sinalizado para o flush");
    t.markPersisted();
    CHECK(!t.shouldPersistNow(), "apos gravar, o estado fica limpo");
}

// ---------------------------------------------------------------------
// 6) Mudanca de causa e deteccao de falha
// ---------------------------------------------------------------------
static void testCauseChangeAndFaults() {
    SECTION("Causa de reinicio - mudanca de causa");

    HefResetTracker t;
    t.begin(HEF_RST_POWERON, 100);
    t.markPersisted();

    // Mesma causa: nao grava.
    CHECK(!t.begin(HEF_RST_POWERON, 100), "mesma causa nao grava");

    // Brownout: muda, grava.
    CHECK(t.begin(HEF_RST_BROWNOUT, 100), "brownout grava (causa mudou)");
    t.markPersisted();

    // WDT: muda, grava.
    CHECK(t.begin(HEF_RST_TASK_WDT, 100), "wdt grava (causa mudou)");
    t.markPersisted();

    // De volta ao brownout: muda, grava.
    CHECK(t.begin(HEF_RST_BROWNOUT, 100), "volta ao brownout grava");

    // A ultima causa persistida acompanha a ultima causa.
    t.markPersisted();
    CHECK(t.counters().lastPersisted == HEF_RST_BROWNOUT,
          "causa persistida acompanha a causa atual");

    // As falhas de software ficam visiveis nos contadores.
    HefResetTracker u;
    u.begin(HEF_RST_TASK_WDT, 1);
    u.begin(HEF_RST_PANIC, 1);
    CHECK(u.counters().wdtResets == 1, "wdt contabilizado");
    CHECK(u.counters().panics == 1, "panic contabilizada");
    CHECK(u.counters().boots == 2, "dois boots no total");
}

// ---------------------------------------------------------------------
// 7) Acao de reinicio intencional
// ---------------------------------------------------------------------
static void testResetIntent() {
    SECTION("Causa de reinicio - acao intencional");

    // Um reinicio pedido pelo operador e' distinguivel de um travamento.
    HefResetIntent intent;
    memset(&intent, 0, sizeof(intent));
    intent.kind     = HEF_RESET_INTENT_USER;
    intent.reason   = HEF_RST_SW;
    intent.sequence = 42;

    CHECK(intent.kind == HEF_RESET_INTENT_USER, "intent de usuario");
    CHECK(intent.kind != HEF_RESET_INTENT_FAULT, "nao e' fault");
    CHECK(intent.sequence == 42, "sequence preservado");

    // Um reinicio por falha automatica e' um fault.
    HefResetIntent fault;
    memset(&fault, 0, sizeof(fault));
    fault.kind     = HEF_RESET_INTENT_FAULT;
    fault.reason   = HEF_RST_PANIC;
    fault.sequence = 43;
    CHECK(fault.kind == HEF_RESET_INTENT_FAULT, "intent de fault");
    CHECK(hefResetIsFault(fault.reason), "a causa do fault e' uma falha");

    // O intent "nenhum" e' o estado inicial.
    HefResetIntent none;
    memset(&none, 0, sizeof(none));
    none.kind = HEF_RESET_INTENT_NONE;
    CHECK(none.kind == HEF_RESET_INTENT_NONE, "intent vazio");
}

// ---------------------------------------------------------------------
// 7-bis) A intencao tem de corresponder a ESTE boot
// ---------------------------------------------------------------------
// A intencao e' gravada antes do reinicio, com o numero do boot que o
// reinicio produziria. No boot seguinte ela e' lida e CONSUMIDA.
//
// Sem a checagem de sequence, um `reboot` do operador deixaria um
// intent "pendente" que continuaria aparecendo em TODOS os boots
// seguintes — dizendo "reinicio solicitado pelo operador" em reinicios
// que foram, na verdade, travamentos. Informacao errada e' pior do que
// a ausencia dela.
static void testResetIntentMatching() {
    SECTION("Causa de reinicio - a intencao corresponde a este boot");

    HefResetIntent intent;
    memset(&intent, 0, sizeof(intent));
    intent.kind     = HEF_RESET_INTENT_USER;
    intent.reason   = HEF_RST_SW;
    intent.sequence = 42;

    CHECK(hefResetIntentMatches(intent, 42),
          "a intencao casa com o boot que ela produziu");
    CHECK(!hefResetIntentMatches(intent, 41),
          "nao casa com um boot anterior");
    CHECK(!hefResetIntentMatches(intent, 43),
          "nao casa com um boot posterior (intencao consumida)");

    // Intent "nenhum" nunca casa.
    HefResetIntent none;
    memset(&none, 0, sizeof(none));
    none.kind     = HEF_RESET_INTENT_NONE;
    none.sequence = 42;
    CHECK(!hefResetIntentMatches(none, 42),
          "a intencao vazia nunca casa");

    // Um kind invalido tambem nunca casa (fail-safe).
    HefResetIntent bogus;
    memset(&bogus, 0, sizeof(bogus));
    bogus.kind     = 99;
    bogus.sequence = 42;
    CHECK(!hefResetIntentMatches(bogus, 42),
          "uma intencao com kind invalido nao casa");

    // Falha automatica tambem casa (quando o boot e' o certo).
    HefResetIntent fault;
    memset(&fault, 0, sizeof(fault));
    fault.kind     = HEF_RESET_INTENT_FAULT;
    fault.sequence = 7;
    CHECK(hefResetIntentMatches(fault, 7),
          "a intencao de falha automatica casa com o boot certo");
    CHECK(!hefResetIntentMatches(fault, 8),
          "a intencao de falha automatica nao casa com outro boot");

    // Os nomes das intencoes nao podem ser vazios (o console
    // imprimiria nada).
    CHECK(strlen(hefResetIntentName(HEF_RESET_INTENT_NONE)) > 0,
          "intent NONE tem nome");
    CHECK(strlen(hefResetIntentName(HEF_RESET_INTENT_USER)) > 0,
          "intent USER tem nome");
    CHECK(strlen(hefResetIntentName(HEF_RESET_INTENT_FAULT)) > 0,
          "intent FAULT tem nome");
    CHECK(strlen(hefResetIntentName(99)) > 0,
          "intent invalido tem nome");

    // --- O CICLO COMPLETO ---
    // O operador pede o reinicio; o reinicio acontece; o proximo boot
    // le a intencao, casa com o numero do boot e a consome.
    HefResetTracker t;
    t.begin(HEF_RST_POWERON, 1);
    t.markPersisted();

    HefResetIntent pedido;
    memset(&pedido, 0, sizeof(pedido));
    pedido.kind     = HEF_RESET_INTENT_USER;
    pedido.reason   = HEF_RST_SW;
    pedido.sequence = t.counters().boots + 1;   // o boot que vem

    t.begin(HEF_RST_SW, 1);
    CHECK(hefResetIntentMatches(pedido, t.counters().boots),
          "o boot seguinte casa com o pedido de reinicio");

    // Um boot MAIS DEPOIS (sem novo pedido) nao casa: a intencao foi
    // consumida.
    t.begin(HEF_RST_SW, 1);
    CHECK(!hefResetIntentMatches(pedido, t.counters().boots),
          "um boot posterior nao reaproveita a intencao antiga");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - causa de reinicio e contadores\n");
    printf("=====================================================\n");

    testReasonClassification();
    testCounters();
    testSerialization();
    testCorruptBlob();
    testWearGuard();
    testCauseChangeAndFaults();
    testResetIntent();
    testResetIntentMatching();

    return heftest::summary("causa de reinicio e contadores");
}
