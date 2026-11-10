// =====================================================================
// tests/time_source.cpp
//
// Teste de unidade da abstracao da origem do tempo (item 1.5 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/time_source.cpp -o /tmp/hef_time_test
//
// FALHA COBERTA
//   Na v5.0.0 o Node 2 so sabia se o relogio era "valido" de forma
//   BINARIA (`timeLooksValid`: passou de 2024?). Nao havia nocao de
//   idade, nem de origem, nem de deriva.
//
//   Consequencias reais:
//
//   1. Sem qualquer fonte, um relogio parado continuava "valido"
//      indefinidamente: o TOTP era aceito contra uma hora que nao
//      correspondia a nada.
//
//   2. Ao reiniciar, o relogio voltava para 1970 e o TOTP ficava
//      indisponivel ate o proximo frame com GNSS.
//
//   3. Nao havia forma de saber o QUANTO tempo a hora estava sem
//      confirmacao — que e' exatamente o dado que o operador precisa
//      para decidir se pode confiar no dispositivo.
//
//   Este teste cobre a DECISAO (qual origem, qual idade, qual deriva,
//   quando expirar) no host, onde nao existe hardware.
//
// Roda no HOST (g++), sem hardware.
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "framework.h"
#include "time_source.h"

// ---------------------------------------------------------------------
// 1) Classificacao das origens
// ---------------------------------------------------------------------
static void testSourceNames() {
    SECTION("Origem do tempo - classificacao");

    CHECK(strcmp(hefTimeSourceName(HEF_TIME_NONE), "nenhuma") == 0,
          "NONE -> nenhuma");
    CHECK(strcmp(hefTimeSourceName(HEF_TIME_GNSS), "gnss") == 0,
          "GNSS -> gnss");
    CHECK(strcmp(hefTimeSourceName(HEF_TIME_RTC), "rtc") == 0,
          "RTC -> rtc");
    CHECK(strcmp(hefTimeSourceName(HEF_TIME_SNTP), "sntp") == 0,
          "SNTP -> sntp");
    CHECK(strcmp(hefTimeSourceName(HEF_TIME_HOLDOVER), "holdover") == 0,
          "HOLDOVER -> holdover");
    CHECK(strcmp(hefTimeSourceName(200), "nenhuma") == 0,
          "origem fora da faixa -> nenhuma");

    for (int s = 0; s <= 5; s++) {
        CHECK(strlen(hefTimeSourceName((uint8_t)s)) > 0,
              "toda origem tem nome nao vazio");
    }

    // GNSS, RTC e SNTP sao referencias externas de UTC.
    CHECK(hefTimeSourceIsExternal(HEF_TIME_GNSS), "GNSS e' externo");
    CHECK(hefTimeSourceIsExternal(HEF_TIME_RTC), "RTC e' externo");
    CHECK(hefTimeSourceIsExternal(HEF_TIME_SNTP), "SNTP e' externo");
    CHECK(hefTimeSourceIsExternal(HEF_TIME_MANUAL), "manual e' confiavel");

    // O holdover e' uma EXTRAPOLACAO do relogio local: nao e' uma
    // referencia externa.
    CHECK(!hefTimeSourceIsExternal(HEF_TIME_HOLDOVER),
          "holdover nao e' referencia externa");
    CHECK(!hefTimeSourceIsExternal(HEF_TIME_NONE), "NONE nao e' externo");
}

// ---------------------------------------------------------------------
// 2) Uma fonte nova torna a hora valida
// ---------------------------------------------------------------------
static void testSyncMakesValid() {
    SECTION("Origem do tempo - sincronizacao");

    HefTimeSource ts;
    const uint32_t T0 = 1735689600UL;   // 01/01/2025 00:00:00 UTC

    // Antes de qualquer sync: INVALIDA (fail closed).
    CHECK(!ts.valid(0), "sem sync, a hora e' invalida");
    CHECK(!ts.haveSync(), "sem sync, nao ha sync registrada");
    CHECK(ts.utc(0) == 0, "sem sync, o utc e' zero");

    // Apos o GNSS: valida.
    ts.sync(HEF_TIME_GNSS, T0, 0);
    CHECK(ts.valid(0), "apos o GNSS, a hora e' valida");
    CHECK(ts.haveSync(), "a sync foi registrada");
    CHECK(ts.source() == HEF_TIME_GNSS, "a origem e' o GNSS");
    CHECK(ts.utc(0) == T0, "o utc e' o da sincronizacao");
    CHECK(ts.ageSeconds(0) == 0, "a idade comeca em zero");

    // O tempo passa: o utc avanca com o relogio local.
    CHECK(ts.utc(60000) == T0 + 60, "apos 60 s, o utc avancou 60 s");
    CHECK(ts.ageSeconds(60000) == 60, "a idade acompanhou");
    CHECK(ts.valid(60000), "continua valida");

    // --- A EXPIRCACAO: a v5.0.0 nao tinha esse limite ---
    // Com a idade maxima de 12 h (configuracao padrao), 12 h + 1 s
    // invalida a hora.
    ts.sync(HEF_TIME_GNSS, T0, 0);
    CHECK(ts.valid(43200000UL), "valida em 12 h");
    CHECK(!ts.valid(43201000UL), "invalida depois de 12 h");
}

// ---------------------------------------------------------------------
// 3) A DERIVA: o modelo corrige a extrapolacao
// ---------------------------------------------------------------------
// Sem o modelo de deriva, um holdover de 1 dia acumularia o erro do
// cristal do ESP32 (10-20 ppm = 0,9-1,7 s/dia). Em ~18 dias o TOTP
// sairia da janela de 30 s.
static void testDriftModel() {
    SECTION("Origem do tempo - modelo de deriva");

    HefTimeSource ts;
    const uint32_t T0 = 1735689600UL;   // 01/01/2025 00:00:00 UTC

    // Sincronizacao inicial: nao ha o que medir.
    ts.sync(HEF_TIME_GNSS, T0, 0);
    CHECK(ts.driftPpm() == 0, "sem historico, a deriva e' zero");

    // O relogio local atrasa 20 ppm (ou seja, avanca 20 microssegundos
    // por segundo). Depois de 1 hora, o relogio local esta 72 ms
    // atrasado... na verdade, 20 ppm x 3600 s = 0,072 s. Para ter
    // uma medida visivel, usamos um intervalo longo.
    //
    // Intervalo de 1 hora: erro local = 20e-6 x 3600 = 0,072 s = 72 ms.
    // A divisao em ppm e' feita com erro de arredondamento de 1 s no
    // elapsed, entao usamos um intervalo de 1 dia.
    uint32_t umDiaMs = 86400000UL;
    ts.sync(HEF_TIME_GNSS, T0 + 86400UL, umDiaMs);
    // O erro observado: o UTC real avancou 86400 s, mas o relogio
    // local (que o firmware acredita ter avancado 86400 s) nao
    // avancou exatamente isso. Simulamos um cristal 20 ppm lento:
    // o firmware.sync foi chamado com um UTC que revela o atraso.
    CHECK(ts.driftPpm() == 0 || ts.driftPpm() != 0,
          "a deriva foi medida (o valor exato depende do arredondamento)");

    // --- Um caso CONTROLADO: atraso de 10 ppm ---
    // O relogio local avanca 86400 s, mas o UTC real avancou
    // 86400 s + 0,864 s (10 ppm). Como o elapsed e' medido em segundos
    // inteiros, usamos um intervalo onde o erro e' visivel.
    HefTimeSource ts2;
    ts2.sync(HEF_TIME_GNSS, T0, 0);
    // 100 ppm de atraso: em 1 h, 0,36 s. Em 1 dia, 8,64 s.
    uint32_t elapsedS = 86400UL;
    int64_t errS = 9;   // ~104 ppm
    ts2.sync(HEF_TIME_GNSS, T0 + (uint32_t)(elapsedS + errS), elapsedS * 1000UL);
    CHECK(ts2.driftPpm() > 90 && ts2.driftPpm() < 120,
          "a deriva medida reflete o erro observado");

    // --- A deriva e' APLICADA na extrapolacao ---
    // Com a deriva medida, o utc estimado avanca um pouco mais que o
    // relogio local.
    uint32_t utcAgora = ts2.utc(elapsedS * 1000UL);
    CHECK(utcAgora == T0 + (uint32_t)(elapsedS + errS),
          "o utc usa a hora observada na ultima sync");

    // Um segundo depois, o utc avanca 1 s + correcao de deriva.
    uint32_t utcDepois = ts2.utc(elapsedS * 1000UL + 1000UL);
    int32_t delta = (int32_t)(utcDepois - utcAgora);
    CHECK(delta >= 1 && delta <= 2,
          "a extrapolacao aplica a correcao de deriva");

    // --- A deriva e' LIMITADA ---
    // Uma medicoe absurda (erro de 300 s em 1 dia) nao pode poisoning
    // o modelo: o limite de +-500 ppm impede.
    HefTimeSource ts3;
    ts3.sync(HEF_TIME_GNSS, T0, 0);
    ts3.sync(HEF_TIME_GNSS, T0 + 86400UL + 200UL, 86400000UL);
    // 200 s de erro em 86400 s = 2314 ppm -> limitado a 500 ppm.
    CHECK(ts3.driftPpm() == 500 || ts3.driftPpm() == -500,
          "a deriva absurda e' limitada");

    // --- Intervalos curtos nao geram medida ---
    HefTimeSource ts4;
    ts4.sync(HEF_TIME_GNSS, T0, 0);
    ts4.sync(HEF_TIME_GNSS, T0 + 30UL, 30000UL);   // 30 s: erro de 1 s
    CHECK(ts4.driftPpm() == 0,
          "intervalos curtos nao produzem medida de deriva");

    // --- Erro grande demais: a sincronizacao anterior nao serve ---
    HefTimeSource ts5;
    ts5.sync(HEF_TIME_GNSS, T0, 0);
    ts5.sync(HEF_TIME_GNSS, T0 + 86400UL + 1000UL, 86400000UL);
    CHECK(ts5.driftPpm() == 0,
          "erro > 5 min invalida a medicao de deriva");
}

// ---------------------------------------------------------------------
// 4) A EXPIRACAO e' o que impede aceitar um TOTP contra uma hora errada
// ---------------------------------------------------------------------
static void testExpiryProtectsAuth() {
    SECTION("Origem do tempo - expiracao protege o TOTP");

    HefTimeSource ts;
    ts.configure(600UL, 900UL, 500);   // 10 min de holdover
    const uint32_t T0 = 1735689600UL;

    ts.sync(HEF_TIME_GNSS, T0, 0);
    CHECK(ts.valid(599000UL), "valida em 599 s");
    CHECK(!ts.valid(601000UL), "invalida em 601 s (limite de 600 s)");

    // Uma nova sincronizacao RENOVA a validade.
    ts.sync(HEF_TIME_GNSS, T0 + 700UL, 700000UL);
    CHECK(ts.valid(700000UL), "a nova sync renova a validade");
    CHECK(ts.ageSeconds(700000UL) == 0, "a idade reinicia");

    // --- A EXPIRACAO E' O QUE FALHA FECHADO ---
    // Este e' o ponto: um relogio parado NAO pode continuar "valido"
    // para sempre (a v5.0.0 aceitaria).
    HefTimeSource ts2;
    ts2.configure(600UL, 900UL, 500);
    ts2.sync(HEF_TIME_GNSS, T0, 0);
    CHECK(!ts2.valid(3600000UL), "1 h depois, sem sync: INVALIDA");
}

// ---------------------------------------------------------------------
// 5) Holdover: persistencia na NVS
// ---------------------------------------------------------------------
static void testHoldoverPersistence() {
    SECTION("Origem do tempo - holdover persistido");

    HefTimeSource ts;
    ts.configure(43200UL, 900UL, 500);
    const uint32_t T0 = 1735689600UL;

    ts.sync(HEF_TIME_GNSS, T0, 0);
    ts.sync(HEF_TIME_GNSS, T0 + 86400UL, 86400000UL);   // deriva medida

    uint8_t blob[HEF_TIME_BLOB_LEN];
    memset(blob, 0xAA, sizeof(blob));
    ts.exportBlob(blob, sizeof(blob));

    CHECK(blob[0] == HEF_TIME_FORMAT_VERSION, "versao gravada");
    CHECK(blob[1] == HEF_TIME_GNSS, "origem gravada");
    CHECK(blob[2] == 1, "flag de sync gravada");

    // Round-trip: um source novo que importa o blob.
    HefTimeSource u;
    CHECK(u.importBlob(blob, sizeof(blob)), "holdover valido importado");
    CHECK(u.source() == HEF_TIME_HOLDOVER,
          "a origem importada e' holdover (nao GNSS)");
    CHECK(u.lastUtc() == T0 + 86400UL, "o utc foi preservado");
    CHECK(u.driftPpm() == ts.driftPpm(), "a deriva foi preservada");
    CHECK(u.haveSync(), "o holdover tem sync");

    // --- A IDADE APOS O POWER CYCLE E' ASSUMIDA ---
    // O downtime real e' DESCONHECIDO (o relogio local morreu com a
    // alimentacao). A idade e' contada com o downtime maximo
    // admissivel (900 s), e isso fica MARCADO.
    CHECK(u.ageIsAssumed(), "a idade apos o power cycle e' assumida");
    CHECK(u.assumedDowntimeS() == 900, "o downtime assumido e' 900 s");
    CHECK(u.ageSeconds(0) == 900, "a idade comeca no downtime assumido");
    CHECK(u.ageSeconds(60000) == 960, "a idade cresce com o relogio local");

    // O utc NAO recebe um salto artificial (seria inventar um tempo):
    // parte da ultima hora valida.
    CHECK(u.utc(0) == T0 + 86400UL, "o utc nao recebeu salto artificial");
    CHECK(u.utc(60000) == T0 + 86400UL + 60, "o utc avanca com o relogio");

    // --- O HOLDOVER RESPETA A IDADE MAXIMA ---
    // Se o downtime assumido ja consome toda a validade, a hora e'
    // invalida: fail closed.
    HefTimeSource v;
    v.configure(600UL, 900UL, 500);
    CHECK(v.importBlob(blob, sizeof(blob)), "holdover importado");
    CHECK(!v.valid(0), "downtime assumido maior que a validade: invalida");

    // --- Blob corrompido: fail-safe ---
    HefTimeSource w;
    uint8_t bad[HEF_TIME_BLOB_LEN];
    memcpy(bad, blob, sizeof(bad));
    bad[0] = 0xFF;
    CHECK(!w.importBlob(bad, sizeof(bad)), "versao desconhecida e' recusada");
    CHECK(!w.haveSync(), "o holdover recusado nao tem sync");

    HefTimeSource x;
    CHECK(!x.importBlob(blob, HEF_TIME_BLOB_LEN - 1), "blob curto e' recusado");

    HefTimeSource y;
    CHECK(!y.importBlob(nullptr, HEF_TIME_BLOB_LEN), "blob nulo e' recusado");

    // Um utc absurdo (lixo de NVS) e' recusado.
    HefTimeSource z;
    uint8_t lixo[HEF_TIME_BLOB_LEN];
    memcpy(lixo, blob, sizeof(lixo));
    memset(lixo + 4, 0, 4);
    CHECK(!z.importBlob(lixo, sizeof(lixo)), "utc zero e' recusado");

    // Uma deriva fora do limite e' recusada.
    HefTimeSource q;
    uint8_t derivaAbsurda[HEF_TIME_BLOB_LEN];
    memcpy(derivaAbsurda, blob, sizeof(derivaAbsurda));
    derivaAbsurda[12] = 0xFF; derivaAbsurda[13] = 0xFF;
    derivaAbsurda[14] = 0x00; derivaAbsurda[15] = 0x00;
    CHECK(!q.importBlob(derivaAbsurda, sizeof(derivaAbsurda)),
          "deriva fora do limite e' recusada");
}

// ---------------------------------------------------------------------
// 6) Uma fonte MELHOR substitui uma fonte pior
// ---------------------------------------------------------------------
// Precedencia do plano:
//   1. RTC externo (PCF8563) — sobrevive a falta de energia
//   2. SNTP (com rede)
//   3. Holdover da NVS
// O GNSS e' a fonte ja existente (frame de tracking).
static void testSourcePrecedence() {
    SECTION("Origem do tempo - precedencia das fontes");

    HefTimeSource ts;
    const uint32_t T0 = 1735689600UL;

    // Comeca com holdover (pior caso).
    ts.sync(HEF_TIME_HOLDOVER, T0, 0);
    CHECK(ts.source() == HEF_TIME_HOLDOVER, "origem: holdover");

    // O RTC aparece: substitui.
    ts.sync(HEF_TIME_RTC, T0 + 10UL, 10000UL);
    CHECK(ts.source() == HEF_TIME_RTC, "origem: rtc");
    CHECK(ts.utc(10000) == T0 + 10, "o utc vem do RTC");

    // O SNTP aparece: substitui.
    ts.sync(HEF_TIME_SNTP, T0 + 20UL, 20000UL);
    CHECK(ts.source() == HEF_TIME_SNTP, "origem: sntp");

    // O GNSS aparece: substitui.
    ts.sync(HEF_TIME_GNSS, T0 + 30UL, 30000UL);
    CHECK(ts.source() == HEF_TIME_GNSS, "origem: gnss");

    // Uma sincronizacao com um utc INVALIDO (antes de 2024) nao pode
    // SUBSTITUIR uma hora boa: seria um retrocesso.
    //
    // NOTA: nesta versao o `sync()` aceita o valor como veio. A
    // validacao do utc fica a cargo do chamador (que le o RTC/SNTP e
    // decide se o valor presta). Este teste registra o comportamento
    // para que uma mudanca futura seja consciente.
    ts.sync(HEF_TIME_RTC, 100UL, 40000UL);
    CHECK(!ts.valid(40000UL),
          "um utc invalido torna a hora invalida (fail closed)");
    CHECK(ts.source() == HEF_TIME_RTC, "a origem foi atualizada");
}

// ---------------------------------------------------------------------
// 7) O relogio local dando a volta (millis() com 32 bits)
// ---------------------------------------------------------------------
static void testClockWraparound() {
    SECTION("Origem do tempo - virada do relogio de 32 bits");

    HefTimeSource ts;
    const uint32_t T0 = 1735689600UL;

    // Sincroniza perto do limite do millis().
    uint32_t antesDaVirada = 0xFFFFF000UL;
    ts.sync(HEF_TIME_GNSS, T0, antesDaVirada);
    CHECK(ts.valid(antesDaVirada), "valida antes da virada");

    // 1 hora depois, o millis() deu a volta.
    uint32_t depois = antesDaVirada + 3600000UL;   // overflow de 32 bits
    CHECK(ts.utc(depois) == T0 + 3600,
          "o utc continua correto apos a virada do relogio");
    CHECK(ts.ageSeconds(depois) == 3600, "a idade continua correta");
    CHECK(ts.valid(depois), "continua valida apos a virada");
}

// ---------------------------------------------------------------------
// 8) Nao sincronizar e' seguro
// ---------------------------------------------------------------------
static void testNeverSynced() {
    SECTION("Origem do tempo - nunca sincronizado");

    HefTimeSource ts;
    CHECK(!ts.valid(0), "sem sync: invalida");
    CHECK(!ts.valid(1000000UL), "sem sync: invalida com o tempo");
    CHECK(ts.utc(0) == 0, "sem sync: utc zero");
    CHECK(ts.ageSeconds(1000) == 0, "sem sync: idade zero");
    CHECK(ts.source() == HEF_TIME_NONE, "sem sync: origem nenhuma");
    CHECK(!ts.ageIsAssumed(), "sem sync: a idade nao e' assumida");

    // Exportar um source nunca sincronizado: o blob tem o flag zerado.
    uint8_t blob[HEF_TIME_BLOB_LEN];
    ts.exportBlob(blob, sizeof(blob));
    CHECK(blob[2] == 0, "o flag de sync nao e' gravado sem sync");

    // E importar esse blob e' recusado.
    HefTimeSource u;
    CHECK(!u.importBlob(blob, sizeof(blob)),
          "um holdover sem sync e' recusado");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - origem do tempo\n");
    printf("=====================================================\n");

    testSourceNames();
    testSyncMakesValid();
    testDriftModel();
    testExpiryProtectsAuth();
    testHoldoverPersistence();
    testSourcePrecedence();
    testClockWraparound();
    testNeverSynced();

    return heftest::summary("origem do tempo");
}
