// =====================================================================
// tests/rtc_pcf8563.cpp
//
// Teste de unidade do codec do RTC externo PCF8563 (item 1.5 do plano).
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/rtc_pcf8563.cpp -o /tmp/hef_rtc_test
//
// FALHA COBERTA
//   O PCF8563 guarda a data e a hora em 7 registros BCD (0x02..0x08),
//   com bits de flag e bits reservados que nao sao dados. Um codec que:
//     - leia os registros no offset errado (0x00 em vez de 0x02);
//     - ignore o flag OSF (alimentacao perdida);
//     - ignore bits reservados;
//     - aceite o modo 12 h como 24 h;
//     - aceite uma data impossivel (29/02 em ano nao bissexto, mes 13);
//     - nao verifique o dia da semana;
//   produz uma hora ERRADA ou INCONFIAVEL sem sinalizar o erro.
//
//   A hora errada e' a falha mais grave do item 1.5: ela nao quebra o
//   sistema (o login por TOTP continua "funcionando"), mas quebra a
//   AUTENTICACAO — o operador e' aceito ou recusado por um relogio
//   que mente.
//
// Roda no HOST (g++), sem hardware.
// =====================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "framework.h"
#include "rtc_pcf8563.h"

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
// Monta os 7 registros (0x02..0x08) para um Unix UTC conhecido.
// O OSF e' limpo (hora confiavel).
static void makeRegs(uint32_t utc, uint8_t* regs) {
    bool ok = hefUnixToPcf8563(utc, regs);
    if (!ok) memset(regs, 0, HEF_PCF8563_TIME_REGS);
}

// ---------------------------------------------------------------------
// 1) BCD e calendarios
// ---------------------------------------------------------------------
static void testBcdAndCalendar() {
    SECTION("PCF8563 - BCD e calendario");

    CHECK(hefBcdToBin(0x00) == 0, "BCD 0x00 -> 0");
    CHECK(hefBcdToBin(0x09) == 9, "BCD 0x09 -> 9");
    CHECK(hefBcdToBin(0x10) == 10, "BCD 0x10 -> 10");
    CHECK(hefBcdToBin(0x59) == 59, "BCD 0x59 -> 59");
    CHECK(hefBcdToBin(0x99) == 99, "BCD 0x99 -> 99");

    CHECK(hefBinToBcd(0) == 0x00, "0 -> 0x00");
    CHECK(hefBinToBcd(9) == 0x09, "9 -> 0x09");
    CHECK(hefBinToBcd(10) == 0x10, "10 -> 0x10");
    CHECK(hefBinToBcd(59) == 0x59, "59 -> 0x59");
    CHECK(hefBinToBcd(99) == 0x99, "99 -> 0x99");

    // Round-trip BCD para todos os valores 0..99.
    for (int v = 0; v <= 99; v++) {
        uint8_t b = hefBinToBcd((uint8_t)v);
        CHECK(hefBcdValid(b), "o BCD gerado e' valido");
        CHECK(hefBcdToBin(b) == (uint8_t)v, "round-trip BCD");
    }

    CHECK(!hefBcdValid(0x0A), "0x0A nao e' BCD valido");
    CHECK(!hefBcdValid(0xA0), "0xA0 nao e' BCD valido");
    CHECK(!hefBcdValid(0xFF), "0xFF nao e' BCD valido");

    // Ano bissexto.
    CHECK(hefIsLeapYear(2024), "2024 e' bissexto");
    CHECK(!hefIsLeapYear(2023), "2023 nao e' bissexto");
    CHECK(!hefIsLeapYear(2100), "2100 nao e' bissexto (regra dos 100)");
    CHECK(hefIsLeapYear(2000), "2000 e' bissexto (regra dos 400)");

    // Dias no mes.
    CHECK(hefDaysInMonth(2024, 2) == 29, "fevereiro 2024 tem 29 dias");
    CHECK(hefDaysInMonth(2023, 2) == 28, "fevereiro 2023 tem 28 dias");
    CHECK(hefDaysInMonth(2024, 1) == 31, "janeiro tem 31 dias");
    CHECK(hefDaysInMonth(2024, 4) == 30, "abril tem 30 dias");
    CHECK(hefDaysInMonth(2024, 0) == 0, "mes 0 e' invalido");
    CHECK(hefDaysInMonth(2024, 13) == 0, "mes 13 e' invalido");

    // Dia da semana.
    // 2024-01-01 00:00:00 UTC foi uma segunda-feira (1).
    CHECK(hefWeekdayFromUnix(1704067200UL) == 1,
          "2024-01-01 foi uma segunda-feira");
}

// ---------------------------------------------------------------------
// 2) Round-trip Unix <-> registros
// ---------------------------------------------------------------------
static void testRoundTrip() {
    SECTION("PCF8563 - round-trip Unix <-> registros");

    // Um conjunto de instantes conhecidos.
    const uint32_t instantes[] = {
        1704067201UL,   // 2024-01-01 00:00:01 (segunda)
        1704153600UL,   // 2024-01-02 00:00:00 (terca)
        1709251200UL,   // 2024-03-01 00:00:00 (sexta, apos bissexto)
        1709164800UL,   // 2024-02-29 00:00:00 (quinta, bissexto)
        1719792000UL,   // 2024-07-01 00:00:00
        1735689600UL,   // 2025-01-01 00:00:00 (quarta)
        1767225600UL,   // 2026-01-01 00:00:00 (quinta)
        1830297600UL,   // 2028-01-01 00:00:00 (sabado)
        1893456000UL,   // 2030-01-01 00:00:00 (terca)
        2145916800UL,   // 2038-01-01 00:00:00
    };

    for (size_t i = 0; i < sizeof(instantes)/sizeof(instantes[0]); i++) {
        uint8_t regs[HEF_PCF8563_TIME_REGS];
        uint32_t utc = instantes[i];
        uint32_t out = 0;

        CHECK(hefUnixToPcf8563(utc, regs), "codificacao ok");
        // OSF deve estar limpo apos a escrita.
        CHECK((regs[0] & HEF_PCF8563_SEC_OSF) == 0,
              "OSF limpo apos a escrita");
        CHECK(hefPcf8563ToUnix(regs, &out), "decodificacao ok");
        CHECK(out == utc, "round-trip Unix <-> registros");
    }

    // O read-back de uma escrita correta deve bater.
    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint8_t readBack[HEF_PCF8563_TIME_REGS];
    makeRegs(1735689600UL, regs);
    memcpy(readBack, regs, sizeof(regs));
    CHECK(hefPcf8563ReadMatches(regs, readBack),
          "read-back identico bate");
    readBack[0] ^= 0x01;
    CHECK(!hefPcf8563ReadMatches(regs, readBack),
          "read-back diferente nao bate");

    // Controle 1 para arrancar: STOP limpo, 24 h.
    uint8_t ctrl1 = hefPcf8563Ctrl1Start();
    CHECK((ctrl1 & HEF_PCF8563_CTRL1_STOP) == 0, "STOP limpo");
}

// ---------------------------------------------------------------------
// 3) Flag OSF: alimentacao perdida
// ---------------------------------------------------------------------
static void testOsfFlag() {
    SECTION("PCF8563 - flag OSF (alimentacao perdida)");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0xDEADBEEFUL;
    makeRegs(1735689600UL, regs);

    // Com o OSF limpo, a hora e' confiavel.
    CHECK(hefPcf8563ToUnix(regs, &out), "OSF limpo: hora confiavel");

    // Com o OSF ligado, o PCF8563 perdeu a alimentacao: o horario
    // guardado e' INCONFIAVEL. A decodificacao deve FALHAR.
    out = 0xDEADBEEFUL;
    regs[0] |= HEF_PCF8563_SEC_OSF;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "OSF ligado: hora inconfiavel (recusada)");
    CHECK(out == 0xDEADBEEFUL,
          "com OSF ligado, o UTC de saida nao e' alterado");
}

// ---------------------------------------------------------------------
// 4) Data impossivel
// ---------------------------------------------------------------------
static void testImpossibleDates() {
    SECTION("PCF8563 - data impossivel");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0;

    // Base: 2024-02-29 12:00:00 (bissexto, valido).
    // 2024-02-29 12:00:00 UTC = 1709208000
    const uint32_t bissexto = 1709208000UL;
    makeRegs(bissexto, regs);
    CHECK(hefPcf8563ToUnix(regs, &out), "29/02/2024 e' valido (bissexto)");

    // 29/02 em ano NAO bissexto: impossivel.
    // 2023 nao e' bissexto -> ano 23, dia 29, mes 02.
    makeRegs(bissexto, regs);
    regs[6] = hefBinToBcd(23); // ano 2023
    regs[4] = hefWeekdayFromCivil(2023, 2, 28); // nao bate, mas o dia ja e' invalido
    // Ajusta o dia da semana para "o que seria" 29/02/2023 (coerente com
    // a data civil calculada), para isolar o teste do dia impossivel.
    regs[4] = hefWeekdayFromCivil(2023, 2, 29 % 29 == 0 ? 28 : 29);
    // O dia 29 em fevereiro de 2023 nao existe.
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "29/02/2023 e' impossivel (nao bissexto)");

    // Mes 13.
    makeRegs(1735689600UL, regs);
    regs[5] = hefBinToBcd(13); // mes impossivel
    CHECK(!hefPcf8563ToUnix(regs, &out), "mes 13 e' impossivel");

    // Mes 0.
    makeRegs(1735689600UL, regs);
    regs[5] = hefBinToBcd(0);
    CHECK(!hefPcf8563ToUnix(regs, &out), "mes 0 e' impossivel");

    // Dia 0.
    makeRegs(1735689600UL, regs);
    regs[3] = hefBinToBcd(0);
    CHECK(!hefPcf8563ToUnix(regs, &out), "dia 0 e' impossivel");

    // Dia 32.
    makeRegs(1735689600UL, regs);
    regs[3] = hefBinToBcd(32);
    regs[4] = 0; // dia da semana qualquer (vai falhar antes ou no WD)
    CHECK(!hefPcf8563ToUnix(regs, &out), "dia 32 e' impossivel");

    // 31 de abril (abril tem 30).
    makeRegs(1714521600UL, regs); // 2024-05-01
    regs[3] = hefBinToBcd(31);
    regs[5] = hefBinToBcd(4); // abril
    regs[4] = hefWeekdayFromCivil(2024, 4, 30); // tentativa de coerencia
    CHECK(!hefPcf8563ToUnix(regs, &out), "31 de abril e' impossivel");

    // Hora 24, minuto 60, segundo 60.
    makeRegs(1735689600UL, regs);
    regs[2] = hefBinToBcd(24);
    CHECK(!hefPcf8563ToUnix(regs, &out), "hora 24 e' impossivel");

    makeRegs(1735689600UL, regs);
    regs[1] = hefBinToBcd(60);
    CHECK(!hefPcf8563ToUnix(regs, &out), "minuto 60 e' impossivel");

    makeRegs(1735689600UL, regs);
    regs[0] = hefBinToBcd(60); // OSF limpo, segundo invalido
    CHECK(!hefPcf8563ToUnix(regs, &out), "segundo 60 e' impossivel");
}

// ---------------------------------------------------------------------
// 5) Bits reservados e modo 12 h
// ---------------------------------------------------------------------
static void testReservedBitsAndMode() {
    SECTION("PCF8563 - bits reservados e modo 12 h");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0;
    makeRegs(1735689600UL, regs);

    // Bit reservado do minuto ligado.
    regs[1] |= 0x80;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "bit reservado do minuto ligado: recusado");

    // Bit reservado da hora (bit 5) ligado.
    makeRegs(1735689600UL, regs);
    regs[2] |= 0x20;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "bit reservado da hora ligado: recusado");

    // Modo 12 h (bit 6 da hora).
    makeRegs(1735689600UL, regs);
    regs[2] |= 0x40;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "modo 12 h nao e' suportado: recusado");

    // Bits reservados do dia da semana.
    makeRegs(1735689600UL, regs);
    regs[4] |= 0x08;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "bit reservado do dia da semana ligado: recusado");

    // Bits reservados do mes.
    makeRegs(1735689600UL, regs);
    regs[5] |= 0x20;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "bit reservado do mes ligado: recusado");
}

// ---------------------------------------------------------------------
// 6) Dia da semana incoerente
// ---------------------------------------------------------------------
static void testWeekdayCoherence() {
    SECTION("PCF8563 - dia da semana coerente");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0;

    // 2025-01-01 foi uma quarta-feira (3).
    makeRegs(1735689600UL, regs);
    CHECK(hefPcf8563ToUnix(regs, &out), "dia da semana correto: aceito");

    // Forca um dia da semana errado.
    makeRegs(1735689600UL, regs);
    regs[4] = (regs[4] + 1) % 7;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "dia da semana incoerente: recusado");
}

// ---------------------------------------------------------------------
// 7) Flag de seculo (2100+)
// ---------------------------------------------------------------------
static void testCenturyFlag() {
    SECTION("PCF8563 - flag de seculo");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0;

    // 2100-01-01 00:00:00 UTC (sexto-feira, nao bissexto).
    // Calculo: dias de 1970-01-01 a 2100-01-01.
    // 2100 nao e' bissexto, entao 1 de marco vem 1 dia "antes" no padrao.
    // Valor conhecido: 4102444800.
    const uint32_t utc2100 = 4102444800UL;
    CHECK(hefUnixToPcf8563(utc2100, regs), "2100-01-01 codificavel");
    CHECK((regs[5] & HEF_PCF8563_MON_CENTURY) != 0,
          "flag de seculo ligado para 2100");
    CHECK(hefPcf8563ToUnix(regs, &out), "2100-01-01 decodificavel");
    CHECK(out == utc2100, "round-trip 2100");

    // 2099: flag de seculo limpo.
    // 2099-01-01 00:00:00 UTC = 4070908800.
    const uint32_t utc2099 = 4070908800UL;
    CHECK(hefUnixToPcf8563(utc2099, regs), "2099-01-01 codificavel");
    CHECK((regs[5] & HEF_PCF8563_MON_CENTURY) == 0,
          "flag de seculo limpo para 2099");
    CHECK(hefPcf8563ToUnix(regs, &out), "2099-01-01 decodificavel");
    CHECK(out == utc2099, "round-trip 2099");
}

// ---------------------------------------------------------------------
// 8) Entradas invalidas e limites
// ---------------------------------------------------------------------
static void testInvalidInputs() {
    SECTION("PCF8563 - entradas invalidas");

    uint8_t regs[HEF_PCF8563_TIME_REGS];
    uint32_t out = 0xDEADBEEFUL;

    CHECK(!hefPcf8563ToUnix(nullptr, &out), "regs nulo: recusado");
    CHECK(!hefPcf8563ToUnix(regs, nullptr), "out nulo: recusado");

    // Todos os bytes zero: OSF limpo, mas data impossivel (ano 2000,
    // mes 0, dia 0).
    memset(regs, 0, sizeof(regs));
    CHECK(!hefPcf8563ToUnix(regs, &out), "registros zerados: recusado");

    // Todos os bytes 0xFF: OSF ligado, BCD invalido.
    memset(regs, 0xFF, sizeof(regs));
    CHECK(!hefPcf8563ToUnix(regs, &out), "registros 0xFF: recusado");

    // Anterior a 2024: recusado (lixo de NVS / RTC nunca inicializado).
    CHECK(!hefUnixToPcf8563(1704067200UL, regs),
          "2024-01-01 00:00:00 (limite) e' recusado");
    CHECK(!hefUnixToPcf8563(1000UL, regs),
          "Unix antigo e' recusado");
    CHECK(!hefUnixToPcf8563(0UL, regs), "Unix zero e' recusado");

    // Um registro valido mas com ano anterior a 2024 tambem deve ser
    // recusado (ex.: 2023-12-31).
    // 2023-12-31 23:59:59 UTC = 1704067199
    // Nao podemos codificar via hefUnixToPcf8563 (ele recusa), entao
    // montamos manualmente.
    memset(regs, 0, sizeof(regs));
    regs[0] = hefBinToBcd(59); // seg
    regs[1] = hefBinToBcd(59); // min
    regs[2] = hefBinToBcd(23); // hora
    regs[3] = hefBinToBcd(31); // dia
    regs[4] = 0;               // domingo (2023-12-31 foi domingo)
    regs[5] = hefBinToBcd(12); // mes
    regs[6] = hefBinToBcd(23); // ano 2023
    // Confirma que o dia da semana bate: 2023-12-31 foi domingo (0).
    CHECK(hefWeekdayFromCivil(2023, 12, 31) == 0,
          "2023-12-31 foi domingo");
    out = 0xDEADBEEFUL;
    CHECK(!hefPcf8563ToUnix(regs, &out),
          "data anterior a 2024 e' recusada");
}

int main() {
    printf("=====================================================\n");
    printf(" Hefestos SIGINT - codec RTC PCF8563\n");
    printf("=====================================================\n");

    testBcdAndCalendar();
    testRoundTrip();
    testOsfFlag();
    testImpossibleDates();
    testReservedBitsAndMode();
    testWeekdayCoherence();
    testCenturyFlag();
    testInvalidInputs();

    return heftest::summary("codec RTC PCF8563");
}
