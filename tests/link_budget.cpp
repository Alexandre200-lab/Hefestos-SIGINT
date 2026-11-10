// =====================================================================
// tests/link_budget.cpp
//
// Teste de unidade do calculo de tempo no ar, duty cycle e orcamento de RF.
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/link_budget.cpp -o /tmp/hef_budget_test
//
// A formula e' validada contra a tabela de airtime do RP002 (LoRaWAN
// Regional Parameters, EU868) - os MISMOS valores usados pelo
// tools/airtime.py --selftest. Se o firmware e' alterado, os dois
// precisam concordar com a norma.
//
// Este teste existe porque a v5.0.0 operava com SF10 a 1 Hz: um duty
// cycle de 225% e' fisicamente impossivel e NENHUM teste/build apontava
// o problema.
#include <cstdio>
#include <cstdint>

#include "framework.h"
#include "link_budget.h"
#include "band_plan.h"
#include "link_protocol.h"

// ---------------------------------------------------------------------
// Referencia oficial: RP002 EU868 (DR0=SF7/125, DR2=SF10/125, DR5=SF12/125)
// ---------------------------------------------------------------------
struct Ref {
    uint8_t  sf;
    uint16_t pl;
    uint32_t airtimeUs;
};

static const Ref RP002[] = {
    { 7,  12,    56576UL },
    { 7,  51,   158976UL },
    { 7, 115,   322816UL },
    {10,  12,   452608UL },
    {10,  51,  1271808UL },
    {10, 115,  2582528UL },
    {12,  12,  1810432UL },
    {12,  51,  5087232UL },
    {12, 115, 10330112UL },
};

// ---------------------------------------------------------------------
// 1) Formula do tempo no ar contra a tabela oficial
// ---------------------------------------------------------------------
static void testAgainstRp002() {
    SECTION("Tempo no ar contra a tabela RP002");

    for (size_t i = 0; i < sizeof(RP002) / sizeof(RP002[0]); i++) {
        HefLinkParams p;
        p.sf = RP002[i].sf;
        p.bwKHz = 125;
        p.crNum = 4;
        uint32_t got = HefLinkBudget::airtimeUs(RP002[i].pl, p);
        char msg[96];
        snprintf(msg, sizeof(msg), "SF%u PL=%u -> %lu us (tabela %lu us)",
                 RP002[i].sf, RP002[i].pl, (unsigned long)got,
                 (unsigned long)RP002[i].airtimeUs);
        CHECK(got == RP002[i].airtimeUs, msg);
    }
}

// ---------------------------------------------------------------------
// 2) Lei de escalonamento 2^(delta SF)
// ---------------------------------------------------------------------
static void testScalingLaw() {
    SECTION("Lei de escalonamento 2^(delta SF)");

    const uint16_t payloads[] = { 12, 54, 115 };
    for (size_t i = 0; i < 3; i++) {
        HefLinkParams p7;
        p7.sf = 7; p7.bwKHz = 125; p7.crNum = 4;
        uint32_t base = HefLinkBudget::airtimeUs(payloads[i], p7);

        bool ok = true;
        for (uint8_t sf = 8; sf <= 12; sf++) {
            HefLinkParams p;
            p.sf = sf; p.bwKHz = 125; p.crNum = 4;
            uint32_t expect = base << (sf - 7);
            if (HefLinkBudget::airtimeUs(payloads[i], p) != expect) ok = false;
        }
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "airtime escala exatamente com 2^(delta SF) para PL=%u",
                 payloads[i]);
        CHECK(ok, msg);
    }
}

// ---------------------------------------------------------------------
// 3) Valores do projeto (frame de 54 B, ACK de 35 B)
// ---------------------------------------------------------------------
static void testProjectValues() {
    SECTION("Valores do projeto Hefestos");

    HefLinkParams sf8;
    sf8.sf = 8; sf8.bwKHz = 125; sf8.crNum = 4;

    HefLinkParams sf10;
    sf10.sf = 10; sf10.bwKHz = 125; sf10.crNum = 4;

    uint32_t track8  = HefLinkBudget::airtimeMs(54, sf8);
    uint32_t ack8    = HefLinkBudget::airtimeMs(33, sf8);
    uint32_t track10 = HefLinkBudget::airtimeMs(54, sf10);
    uint32_t ack10   = HefLinkBudget::airtimeMs(33, sf10);

    // Valores de referencia (tools/airtime.py --selftest confere a
    // equivalencia com a tabela oficial).
    // ACK = cabecalho 15 + payload 2 + tag GCM 16 = 33 bytes (v5.1.0).
    CHECK(track8 == 329UL, "SF8 telemetria (54 B) = 329 ms");
    CHECK(ack8   == 226UL, "SF8 ACK (33 B) = 226 ms");
    CHECK(track10 == 1313UL, "SF10 telemetria (54 B) = 1313 ms");
    CHECK(ack10   == 904UL, "SF10 ACK (33 B) = 904 ms");

    // A configuracao antiga (SF10 a 1 Hz) era fisicamente impossivel.
    float dutyOld = HefLinkBudget::dutyCyclePercent(track10 + ack10, 1000);
    CHECK(dutyOld > 100.0f,
          "configuracao antiga (SF10 @1 Hz) tem duty cycle > 100% (inviavel)");

    // A configuracao nova (SF8 a 1/30 s) e' viavel.
    float dutyNew = HefLinkBudget::dutyCyclePercent(track8 + ack8, 30000);
    CHECK(dutyNew > 1.0f && dutyNew < 2.0f,
          "configuracao nova (SF8 @1/30 s) tem duty cycle entre 1% e 2%");
    CHECK(dutyNew < dutyOld / 100.0f,
          "duty cycle caiu por um fator > 100");

    // Consumo de TX.
    float mahDayOld = HefLinkBudget::txEnergyMah(track10 + ack10, 120.0f)
                      * (86400000.0f / 1000.0f);
    float mahDayNew = HefLinkBudget::txEnergyMah(track8 + ack8, 120.0f)
                      * (86400000.0f / 30000.0f);
    CHECK(mahDayOld > 6000.0f, "consumo TX antigo > 6 Ah/dia (bateria de 6,6 Ah)");
    CHECK(mahDayNew < 100.0f, "consumo TX novo < 100 mAh/dia");
}

// ---------------------------------------------------------------------
// 4) Parametros invalidos
// ---------------------------------------------------------------------
static void testInvalidParams() {
    SECTION("Parametros invalidos");

    HefLinkParams p;
    CHECK(!HefLinkBudget::validSf(5), "SF5 invalido");
    CHECK(!HefLinkBudget::validSf(13), "SF13 invalido");
    CHECK(HefLinkBudget::validSf(8), "SF8 valido");
    CHECK(!HefLinkBudget::validBw(100), "BW100kHz invalido");
    CHECK(HefLinkBudget::validBw(125), "BW125kHz valido");
    CHECK(!HefLinkBudget::validCr(5), "CR5/6 invalido");
    CHECK(HefLinkBudget::validCr(4), "CR4/5 valido");

    HefLinkParams bad;
    bad.sf = 13; bad.bwKHz = 125; bad.crNum = 4;
    CHECK(HefLinkBudget::airtimeUs(54, bad) == 0,
          "params invalidos devolvem airtime 0 (falha fechada)");
}

// ---------------------------------------------------------------------
// 5) Duty cycle e intervalo minimo por perfil
// ---------------------------------------------------------------------
static void testDutyBudget() {
    SECTION("Orcamento de duty cycle por perfil");

    HefLinkParams p;
    p.sf = 8; p.bwKHz = 125; p.crNum = 4;
    uint32_t cycle = HefLinkBudget::airtimeMs(54, p) + HefLinkBudget::airtimeMs(33, p);

    // Perfil 915-ANATEL: 10% de orcamento -> 30 s basta.
    const HefBandProfile* anatel = HefBandPlan::byName("915-ANATEL");
    CHECK(anatel != nullptr, "perfil 915-ANATEL existe");
    if (anatel) {
        uint32_t need = HefLinkBudget::minIntervalForDuty(anatel->dutyLimitPercent, cycle);
        CHECK(need < 30000UL, "915-ANATEL: 30 s cabe no orcamento de 10%");
        CHECK(HefBandPlan::frequencyAllowed(*anatel, 915000),
              "915 MHz e' permitido no perfil 915-ANATEL");
        CHECK(!HefBandPlan::frequencyAllowed(*anatel, 868000),
              "868 MHz NAO e' permitido no perfil 915-ANATEL");
    }

    // Perfil 868-ETSI: 1% de orcamento -> 30 s NAO basta, precisa de ~57 s.
    const HefBandProfile* etsi = HefBandPlan::byName("868-ETSI");
    CHECK(etsi != nullptr, "perfil 868-ETSI existe");
    if (etsi) {
        uint32_t need = HefLinkBudget::minIntervalForDuty(etsi->dutyLimitPercent, cycle);
        CHECK(need > 30000UL, "868-ETSI: 30 s NAO cabe no orcamento de 1%");
        CHECK(need < 120000UL, "868-ETSI: intervalo necessario abaixo de 2 min");
    }

    // Limite zero = nenhuma transmissao.
    CHECK(HefLinkBudget::minIntervalForDuty(0.0f, cycle) == 0xFFFFFFFFUL,
          "duty limit 0 -> nenhum intervalo valido");

    // Perfis: todos dentro das proprias faixas e com parametros validos.
    for (uint8_t i = 0; i < HefBandPlan::count(); i++) {
        const HefBandProfile& pr = HefBandPlan::profiles()[i];
        HefLinkParams pp;
        pp.sf = pr.defaultSf; pp.bwKHz = pr.bwKHz; pp.crNum = pr.crNum;
        char msg[96];
        snprintf(msg, sizeof(msg), "perfil %s: parametros de RF validos", pr.name);
        CHECK(HefLinkBudget::paramsValid(pp), msg);
        snprintf(msg, sizeof(msg), "perfil %s: duty cycle positivo", pr.name);
        CHECK(pr.dutyLimitPercent > 0.0f, msg);
    }

    CHECK(HefBandPlan::active() != nullptr, "perfil ativo existe");
    CHECK(HefBandPlan::byName("inexistente") == nullptr, "perfil inexistente devolve null");
}

// ---------------------------------------------------------------------
// 7) Coerencia entre o protocolo e o calculo de airtime
// ---------------------------------------------------------------------
// O tempo no ar depende do tamanho REAL do frame no ar. Se o payload do
// ACK mudar sem que os testes de airtime sejam atualizados, o duty
// cycle real passa a divergir do planejado sem ninguem perceber.
static void testProtocolCoherence() {
    SECTION("Coerencia protocolo <-> airtime");

    // Cabecalho 15 + payload + tag GCM 16.
    CHECK(HEF_TRACK_FRAME_LEN == 54,
          "frame de telemetria = 54 B (cabecalho 15 + payload 23 + tag 16)");
    CHECK(HEF_ACK_FRAME_LEN == 33,
          "frame de ACK = 33 B (cabecalho 15 + payload 2 + tag 16)");

    // O ACK curto e' o motivo do tamanho: 4 B -> 2 B.
    CHECK(HEF_ACK_PAYLOAD_LEN == 2,
          "payload do ACK reduzido para 2 B (flags + RSSI)");

    // O calculo usa exatamente o tamanho do protocolo.
    HefLinkParams p;
    p.sf = 8; p.bwKHz = 125; p.crNum = 4;
    CHECK(HefLinkBudget::airtimeMs(HEF_TRACK_FRAME_LEN, p) == 329UL,
          "airtime da telemetria usa HEF_TRACK_FRAME_LEN");
    CHECK(HefLinkBudget::airtimeMs(HEF_ACK_FRAME_LEN, p) == 226UL,
          "airtime do ACK usa HEF_ACK_FRAME_LEN");

    // O ACK curto economiza tempo no ar em relacao ao payload de 4 B.
    uint32_t ackLong = HefLinkBudget::airtimeMs(
        HEF_HEADER_LEN + 4 + HEF_TAG_LEN, p);
    uint32_t ackShort = HefLinkBudget::airtimeMs(HEF_ACK_FRAME_LEN, p);
    CHECK(ackShort < ackLong,
          "ACK de 2 B e' mais curto no ar que o de 4 B");
}

// ---------------------------------------------------------------------
// 8) Guard de duty cycle: o firmware IMPEDE a violacao
// ---------------------------------------------------------------------
static void testDutyGuard() {
    SECTION("Guard de duty cycle (janela de 1 h)");

    HefDutyGuard guard;
    const uint32_t minute = 60000UL;

    // Vazio: dentro do limite.
    CHECK(guard.dutyCyclePercent(0) == 0.0f, "janela vazia -> 0%");
    CHECK(guard.allows(0, 500, 10.0f), "primeira transmissao e' permitida");

    // Enche a janela com airtime equivalente a 10% de 1 h = 360 s.
    uint32_t now = 0;
    for (int i = 0; i < 72; i++) {           // 72 x 5 s = 360 s
        guard.record(now, 5000);
        now += 5000;
    }
    float duty = guard.dutyCyclePercent(now);
    CHECK(duty > 9.9f && duty < 10.1f, "duty cycle acumulado ~10%");
    CHECK(!guard.allows(now, 1000, 10.0f),
          "guard RECUSA transmissao que violaria o limite");

    // Passados 60 minutos, os baldes antigos expiram e a janela zera.
    guard.record(now + 61UL * minute, 1000);
    CHECK(guard.dutyCyclePercent(now + 61UL * minute) < 0.1f,
          "janela deslizante expira baldes antigos");

    // Limite zero: nada e' permitido.
    CHECK(!guard.allows(0, 1, 0.0f), "duty limit 0 -> transmission negada");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - orcamento de RF e tempo no ar\n");
    printf("=====================================================\n");

    testAgainstRp002();
    testScalingLaw();
    testProjectValues();
    testInvalidParams();
    testDutyBudget();
    testProtocolCoherence();
    testDutyGuard();

    return heftest::summary("orcamento de RF");
}
