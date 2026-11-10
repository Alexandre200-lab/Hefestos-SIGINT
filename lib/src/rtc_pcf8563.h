// rtc_pcf8563.h - Codec do RTC externo PCF8563 (v5.1.0, item 1.5)
//
// OBJETIVO
//   Item 1.5 do plano: RTC externo PCF8563 no barramento I2C
//   compartilhado com o Si4735 (endereco 0x51), com supercap para
//   manter a hora em falta de energia.
//
// POR QUE UM RTC EXTERNO
//   O relogio interno do ESP32 e' alimentado pelo cristal de 40 MHz e
//   morre com a alimentacao. Num dispositivo de campo que pode ficar
//   dias sem GNSS e sem rede, a unica forma de manter a hora (e, com
//   ela, o TOTP) e' um RTC com bateria ou supercap.
//
// POR QUE UM MODULO SEPARADO E PURO
//   A conversao entre os registros BCD do PCF8563 e o Unix UTC tem as
//   arestas que importam:
//
//     - o bit 7 do registro de SEGUNDOS e' o flag OSF (oscilador
//       parado / alimentacao perdida): com ele ligado, o horario e'
//       INCONFIABLE e nao pode ser usado;
//     - o bit 7 do registro de MES e' o flag de seculo (0 = 20xx,
//       1 = 21xx);
//     - o bit 6 do registro de HORA e' o flag 12/24 h (este codec
//       SÓ entende o modo 24 h);
//     - ha bits RESERVADOS em vários registros: eles devem ser zero,
//       e um valor diferente indica corrupcao (ou um chip de outro
//       fabricante);
//     - o dia da semana e' redundante (o PCF8563 nao o calcula) e
//       precisa ser COERENTE com a data;
//     - o ano e' de 2 digitos;
//     - a data tem de ser validada (mes 13, dia 32, 29 de fevereiro
//       em ano nao bissexto).
//
//   Tudo isso e' aritmeticamente testavel no HOST, onde nao existe
//   barramento I2C. A camada I2C (Wire) fica no firmware.
//
// MAPA DE REGISTROS (datasheet NXP PCF8563)
//
//   0x00  control/status 1   (bit 7 STOP, bit 6 SR, bit 2 24/12,
//                            bit 1 12h, bit 0 C_)
//   0x01  control/status 2   (bit 7 TEST, bit 6 C_)
//   0x02  segundo    bit 7 = OSF, bits 6-0 = BCD
//   0x03  minuto     bit 7 = reservado, bits 6-0 = BCD
//   0x04  hora       bit 6 = 12/24, bit 5 = reservado, bits 4-0 = BCD
//   0x05  dia        bits 6-0 = BCD
//   0x06  dia da semana  bits 2-0 = 0..6, bits 7-3 = reservados
//   0x07  mes        bit 7 = flag de seculo, bits 6-5 = reservados,
//                    bits 4-0 = BCD
//   0x08  ano        bits 7-0 = BCD
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST
// (tests/rtc_pcf8563.cpp).
#ifndef HEF_RTC_PCF8563_H
#define HEF_RTC_PCF8563_H

#include <stdint.h>
#include <stddef.h>

// Endereco I2C do PCF8563 (7 bits).
#define HEF_PCF8563_I2C_ADDR 0x51

// Primeiro registro de data/hora.
//
// ATENCAO: o bloco de data/hora COMECA em 0x02, nao em 0x00. Os
// registros 0x00 e 0x01 sao os de controle/status. Um codec com o
// offset errado leria os controles como se fossem data e hora: o
// resultado seria sempre invalido (o RTC pareceria "ausente"), ou —
// pior — uma data plausivel e errada.
#define HEF_PCF8563_REG_TIME 0x02

// Registro de controle/status 1.
#define HEF_PCF8563_REG_CTRL1 0x00

// Numero de registros de data/hora (segundo..ano).
#define HEF_PCF8563_TIME_REGS 7

// ---------------------------------------------------------------------
// Flags e mascaras
// ---------------------------------------------------------------------
// Flag OSF (oscilador parado / alimentacao perdida) no registro de
// segundo. Com ele ligado, o horario e' INCONFIABLE.
#define HEF_PCF8563_SEC_OSF 0x80

// Mascara dos bits de segundo (sem o OSF).
#define HEF_PCF8563_SEC_MASK 0x7F

// Bit de modo 12/24 h no registro de hora. 0 = 24 h (o unico modo
// que este codec entende).
#define HEF_PCF8563_HOUR_12_24 0x40

// Mascara dos bits de hora (bits 4-0).
#define HEF_PCF8563_HOUR_MASK 0x1F

// Mascara dos bits de dia do mes (bits 6-0).
#define HEF_PCF8563_DAY_MASK 0x7F

// Mascara dos bits de dia da semana (bits 2-0).
#define HEF_PCF8563_WD_MASK 0x07

// Flag de seculo no registro de mes: 0 = 20xx, 1 = 21xx.
#define HEF_PCF8563_MON_CENTURY 0x80

// Mascara dos bits de mes (bits 4-0).
#define HEF_PCF8563_MON_MASK 0x1F

// Mascara dos bits de ano (bits 7-0).
#define HEF_PCF8563_YEAR_MASK 0xFF

// Bits RESERVADOS que devem ser zero em cada registro.
// A leitura de um valor diferente indica corrupcao (ou um chip
// Inve). Ler e descartar o bit nao seria seguro: o dado poderia ser
// silenciosamente errado.
#define HEF_PCF8563_MIN_RESERVED 0x80
#define HEF_PCF8563_HOUR_RESERVED 0x20
#define HEF_PCF8563_WD_RESERVED 0xF8
#define HEF_PCF8563_MON_RESERVED 0x60

// Controle/status 1: bit 7 = STOP (1 = oscilador parado).
#define HEF_PCF8563_CTRL1_STOP 0x80
// Controle/status 1: bit 6 = SR (software reset).
#define HEF_PCF8563_CTRL1_SR 0x40

// ---------------------------------------------------------------------
// Conversao BCD <-> binario
// ---------------------------------------------------------------------
inline uint8_t hefBcdToBin(uint8_t bcd) {
    return (uint8_t)(((bcd >> 4) * 10) + (bcd & 0x0F));
}

inline uint8_t hefBinToBcd(uint8_t bin) {
    return (uint8_t)(((bin / 10) << 4) | (bin % 10));
}

// O nibble alto e' valido? (BCD so vai de 0 a 9)
inline bool hefBcdValid(uint8_t bcd) {
    return ((bcd >> 4) <= 9) && ((bcd & 0x0F) <= 9);
}

// ---------------------------------------------------------------------
// Ano bissexto (regras gregorianas)
// ---------------------------------------------------------------------
inline bool hefIsLeapYear(int32_t year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

// Dias no mes (1..12). Retorna 0 para um mes invalido.
inline uint8_t hefDaysInMonth(int32_t year, uint8_t month) {
    static const uint8_t dias[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    if (month < 1 || month > 12) return 0;
    if (month == 2 && hefIsLeapYear(year)) return 29;
    return dias[month - 1];
}

// ---------------------------------------------------------------------
// Dias desde 1970-01-01 (algoritmo de Howard Hinnant)
// ---------------------------------------------------------------------
inline int64_t hefDaysFromCivil(int32_t y, uint8_t m, uint8_t d) {
    y -= (m <= 2);
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const uint32_t yoe = (uint32_t)(y - era * 400);
    const uint32_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

// Data civil a partir dos dias desde 1970-01-01.
inline void hefCivilFromDays(int64_t z, int32_t* y, uint8_t* m, uint8_t* d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const uint32_t doe = (uint32_t)(z - era * 146097);
    const uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t yy = (int64_t)yoe + era * 400;
    const uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const uint32_t mp = (5 * doy + 2) / 153;
    const uint32_t dd = doy - (153 * mp + 2) / 5 + 1;
    const uint32_t mm = mp + (mp < 10 ? 3 : -9);
    *y = (int32_t)(yy + (mm <= 2));
    *m = (uint8_t)mm;
    *d = (uint8_t)dd;
}

// Dia da semana (0 = domingo) de um Unix UTC.
// 1970-01-01 foi uma quinta-feira (4 na convencao 0=domingo).
inline uint8_t hefWeekdayFromUnix(uint32_t utc) {
    uint32_t days = utc / 86400UL;
    return (uint8_t)((days + 4) % 7);
}

// Dia da semana (0 = domingo) de uma data civil.
inline uint8_t hefWeekdayFromCivil(int32_t y, uint8_t m, uint8_t d) {
    int64_t days = hefDaysFromCivil(y, m, d);
    int64_t wd = (days + 4) % 7;
    if (wd < 0) wd += 7;
    return (uint8_t)wd;
}

// ---------------------------------------------------------------------
// hefPcf8563ToUnix
//
// Decodifica os 7 registros de data/hora em Unix UTC.
//
// Retorna false (e `*outUtc` fica intocado) quando:
//   - o flag OSF esta ligado (o RTC perdeu a alimentacao);
//   - algum registro nao e' BCD valido;
//   - algum bit reservado estiver ligado (corrupcao);
//   - o chip estiver em modo 12 h (nao suportado);
//   - a data e' impossivel (mes 13, dia 32, 29/02 em ano nao
//     bissexto);
//   - o dia da semana for incoerente com a data;
//   - o resultado for anterior a 01/01/2024 (lixo de NVS / RTC nunca
//     inicializado).
// ---------------------------------------------------------------------
inline bool hefPcf8563ToUnix(const uint8_t* regs, uint32_t* outUtc) {
    if (!regs || !outUtc) return false;

    // --- Flag OSF: o horario e' inconfiavel ---
    // O PCF8563 liga o OSF quando o oscilador parou (falta de
    // alimentacao). O horario guardado antes disso NAO e' confiavel.
    if (regs[0] & HEF_PCF8563_SEC_OSF) return false;

    // --- Bits reservados (devem ser zero) ---
    if (regs[1] & HEF_PCF8563_MIN_RESERVED) return false;
    if (regs[2] & HEF_PCF8563_HOUR_RESERVED) return false;
    if (regs[4] & HEF_PCF8563_WD_RESERVED) return false;
    if (regs[5] & HEF_PCF8563_MON_RESERVED) return false;

    // --- Modo 12/24 h: so' 24 h e' suportado ---
    // Em modo 12 h o campo de hora tem semantica diferente (1..12
    // com PM no bit 5 do registro de controle). Interpretar como 24 h
    // daria uma hora errada em vez de um erro visivel.
    if (regs[2] & HEF_PCF8563_HOUR_12_24) return false;

    // --- BCD valido? ---
    if (!hefBcdValid(regs[0] & HEF_PCF8563_SEC_MASK)) return false;
    if (!hefBcdValid(regs[1] & 0x7F)) return false;
    if (!hefBcdValid(regs[2] & HEF_PCF8563_HOUR_MASK)) return false;
    if (!hefBcdValid(regs[3] & HEF_PCF8563_DAY_MASK)) return false;
    if (!hefBcdValid(regs[5] & HEF_PCF8563_MON_MASK)) return false;
    if (!hefBcdValid(regs[6] & HEF_PCF8563_YEAR_MASK)) return false;

    uint8_t sec   = hefBcdToBin(regs[0] & HEF_PCF8563_SEC_MASK);
    uint8_t min   = hefBcdToBin(regs[1] & 0x7F);
    uint8_t hour  = hefBcdToBin(regs[2] & HEF_PCF8563_HOUR_MASK);
    uint8_t day   = hefBcdToBin(regs[3] & HEF_PCF8563_DAY_MASK);
    uint8_t mon   = hefBcdToBin(regs[5] & HEF_PCF8563_MON_MASK);
    uint8_t year2 = hefBcdToBin(regs[6] & HEF_PCF8563_YEAR_MASK);

    // --- Faixas ---
    if (sec > 59) return false;
    if (min > 59) return false;
    if (hour > 23) return false;
    if (mon < 1 || mon > 12) return false;

    // --- Ano ---
    // O flag de seculo do PCF8563 significa "21xx" (a documentacao do
    // chip usa 1 = century = 2100-2199); sem ele, "20xx".
    int32_t year = (regs[5] & HEF_PCF8563_MON_CENTURY)
                     ? (2100 + year2) : (2000 + year2);

    uint8_t maxDay = hefDaysInMonth(year, mon);
    if (maxDay == 0) return false;
    if (day < 1 || day > maxDay) return false;

    // --- O dia da semana e' redundante: se estiver INCOERENTE com a
    //     data, o RTC esta com dado corrompido (ou com a data
    //     ajustada a mao sem atualizar o dia da semana). ---
    uint8_t wd = regs[4] & HEF_PCF8563_WD_MASK;
    if (wd != hefWeekdayFromCivil(year, mon, day)) return false;

    int64_t days = hefDaysFromCivil(year, mon, day);
    int64_t t = days * 86400LL + hour * 3600LL + min * 60LL + sec;
    if (t < 0 || t > 0xFFFFFFFFLL) return false;
    if (t <= 1704067200LL) return false;   // anterior a 01/01/2024

    *outUtc = (uint32_t)t;
    return true;
}

// ---------------------------------------------------------------------
// hefUnixToPcf8563
//
// Codifica Unix UTC nos 7 registros de data/hora.
//
// O flag OSF e' escrito LIGADO? NAO. A escritura da hora no RTC e'
// ela propria a confirmacao de que o chip tem alimentacao e um
// oscilador funcionando. O firmware grava os registros e DEPOIS le
// de volta para confirmar (read-back); se o read-back nao bater, o
// RTC e' considerado nao confiavel e a sincronizacao nao e' aceita.
//
// O bit STOP do registro de controle 1 deve estar limpo antes da
// escrita (ele congela o contador).
//
// Retorna false se o Unix for anterior a 01/01/2024.
// ---------------------------------------------------------------------
inline bool hefUnixToPcf8563(uint32_t utc, uint8_t* regs) {
    if (!regs) return false;
    if (utc <= 1704067200UL) return false;

    int32_t y;
    uint8_t mo, d;
    hefCivilFromDays((int64_t)(utc / 86400UL), &y, &mo, &d);

    uint8_t sec   = (uint8_t)(utc % 60);
    uint8_t min   = (uint8_t)((utc / 60) % 60);
    uint8_t hour  = (uint8_t)((utc / 3600) % 24);
    uint8_t year2 = (uint8_t)(y % 100);

    regs[0] = hefBinToBcd(sec);                    // OSF limpo
    regs[1] = hefBinToBcd(min);
    regs[2] = hefBinToBcd(hour);                   // modo 24 h
    regs[3] = hefBinToBcd(d);
    regs[4] = hefWeekdayFromUnix(utc);
    regs[5] = hefBinToBcd(mo);
    if (y >= 2100) regs[5] |= HEF_PCF8563_MON_CENTURY;
    regs[6] = hefBinToBcd(year2);
    return true;
}

// ---------------------------------------------------------------------
// hefPcf8563Ctrl1Start
//
// Valor do registro de controle 1 para DEIXAR o contador rodando em
// modo 24 h.
//
// O bit STOP (7) congela o contador: com ele ligado, o horario nunca
// avanca e o RTC "parece" funcionar (devolve a ultima hora valida)
// enquanto, na verdade, esta congelado desde a perda de alimentacao.
// O bit SR (6) e' o reset de software: deve ser escrito como 0 no
// uso normal (o chip faz o reset na transicao 0->1).
// ---------------------------------------------------------------------
inline uint8_t hefPcf8563Ctrl1Start() {
    // 24 h (bit 2 = 0), 12h (bit 1 = 0), STOP = 0, SR = 0.
    return 0x00;
}

// ---------------------------------------------------------------------
// hefPcf8563ReadMatches
//
// O read-back da escrita bate com o que foi gravado?
//
// Usado pelo firmware depois de escrever a hora no RTC: um RTC que
// aceitou a escrita mas devolve outra coisa (I2C ruidoso, chip
// travado, outro dispositivo no endereco 0x51) nao pode ser
// considerado confiavel.
// ---------------------------------------------------------------------
inline bool hefPcf8563ReadMatches(const uint8_t* written,
                                  const uint8_t* readBack) {
    if (!written || !readBack) return false;
    for (int i = 0; i < HEF_PCF8563_TIME_REGS; i++) {
        if (written[i] != readBack[i]) return false;
    }
    return true;
}

#endif // HEF_RTC_PCF8563_H
