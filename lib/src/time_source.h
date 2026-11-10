// time_source.h - Abstracao da origem do tempo (v5.1.0, item 1.4/1.5)
//
// OBJETIVO
//   Item 1.5 do plano de escala: apos 10 min sem GNSS e sem rede, o
//   Node 2 deve manter hora valida (+/-30 s) e o login por TOTP
//   continuar funcionando.
//
// O PROBLEMA DA v5.0.0
//   O Node 2 obtinha a hora de UMA unica fonte: o GNSS, via o campo
//   `epochUtc` do frame de tracking. Sem fix GNSS (tunel, building,
//   matao), a hora do sistema continuava valida por um tempo, mas:
//
//     - ao REINICIAR o dispositivo, o relogio voltava para 1970 e o
//       TOTP era recusado ate o proximo frame com GNSS;
//     - sem nenhuma fonte, nao havia como saber QUANTO tempo o
//       relogio tinha avancado: a validacao era binaria
//       (`timeLooksValid`: "passou de 2024?"), sem noção de idade.
//
// A ABSTRACAO
//   Este modulo concentra a DECISAO sobre a origem do tempo e sobre a
//   sua CONFIABILIDADE. Ele nao fala com nenhum hardware: recebe
//   sincronizacoes (GNSS, RTC, SNTP, manual) e responde:
//
//     - `valid()`      -> a hora pode ser usada (inclusive pelo TOTP)?
//     - `utc()`        -> qual e' o UTC estimado agora?
//     - `ageSeconds()` -> ha quanto tempo a hora foi confirmada?
//
//   As fontes externas (RTC PCF8563, SNTP) ficam no firmware; o modulo
//   puro decide o que fazer com o que elas informam.
//
// DERIVA (DRIFT)
//   O relogio local (`millis()`, cristal de 40 MHz do ESP32) tem uma
//   deriva relativa ao UTC. Tipicamente 10-20 ppm (0,9-1,7 s/dia), mas
//   pode chegar a 50 ppm em campo (temperatura, alimentacao).
//
//   A deriva e' MEDIDA a cada sincronizacao: compara-se o UTC observado
//   com o previsto pelo relogio local. A medida alimenta o modelo, que
//   corrige a extrapolacao durante o holdover.
//
//   IMPORTANTE: o que se mede e' a deriva do RELOGIO LOCAL, porque e'
//   ele que conta o tempo durante o holdover. A deriva do RTC externo
//   e' irrelevante para o modelo (o RTC e' lido diretamente).
//
//   Um holdover sem modelo de deriva acumularia 1,7 s/dia — ou seja,
//   em ~18 dias o TOTP sairia da janela de 30 s. Com o modelo, o erro
//   fica na casa de poucos segundos por semana.
//
// FAIL CLOSED
//   A hora e' valida apenas se:
//     - houve alguma sincronizacao; E
//     - a idade esta dentro do limite (`maxAgeS`); E
//     - o UTC estimado passou de 01/01/2024.
//
//   Sem isso, o TOTP e' recusado — comportamento que a v5.0.0 ja
//   tinha (e que e' o CORRETO: aceitar um TOTP contra um relogio
//   errado e' uma falha de autenticacao).
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST
// (tests/time_source.cpp).
#ifndef HEF_TIME_SOURCE_H
#define HEF_TIME_SOURCE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ---------------------------------------------------------------------
// Origem do tempo
// ---------------------------------------------------------------------
enum HefTimeSourceKind {
    HEF_TIME_NONE     = 0,   // nunca sincronizado
    HEF_TIME_MANUAL   = 1,   // console 'settime'
    HEF_TIME_GNSS     = 2,   // frame de tracking com epochUtc
    HEF_TIME_RTC      = 3,   // RTC externo PCF8563
    HEF_TIME_SNTP     = 4,   // SNTP (lwIP)
    HEF_TIME_HOLDOVER = 5    // ultima hora valida, extrapolada
};

// Nome da origem (portugues, sem acentos).
inline const char* hefTimeSourceName(uint8_t source) {
    switch (source) {
        case HEF_TIME_MANUAL:   return "manual";
        case HEF_TIME_GNSS:     return "gnss";
        case HEF_TIME_RTC:      return "rtc";
        case HEF_TIME_SNTP:     return "sntp";
        case HEF_TIME_HOLDOVER: return "holdover";
        default:                return "nenhuma";
    }
}

// A origem e' um relogio EXTERNO (confiavel)?
//
// GNSS, RTC e SNTP sao referencias de UTC. O holdover e' uma
// extrapolacao do relogio local (imprecisa). O manual e' o operador
// (confiavel, mas pode estar errado).
inline bool hefTimeSourceIsExternal(uint8_t source) {
    return source == HEF_TIME_GNSS || source == HEF_TIME_RTC ||
           source == HEF_TIME_SNTP || source == HEF_TIME_MANUAL;
}

// ---------------------------------------------------------------------
// Estado
// ---------------------------------------------------------------------
struct HefTimeState {
    uint8_t  source;      // origem da ultima sincronizacao
    uint32_t utc;         // UTC da ultima sincronizacao
    uint32_t setAtMs;     // millis() no instante da sincronizacao
    int32_t  driftPpm;    // deriva estimada do relogio local (ppm)
    bool     haveSync;    // houve alguma sincronizacao?
};

// Versao do formato serializado do holdover.
#define HEF_TIME_FORMAT_VERSION 1

// Tamanho serializado (little-endian, sem padding): 20 bytes.
#define HEF_TIME_BLOB_LEN 20

// ---------------------------------------------------------------------
// HefTimeSource
// ---------------------------------------------------------------------
class HefTimeSource {
private:
    HefTimeState st_;
    uint32_t maxAgeS_;        // idade maxima aceita (runtime)
    uint32_t maxDowntimeS_;   // downtime assumido apos um power cycle
    int32_t  maxDriftPpm_;    // limite da deriva estimada
    uint32_t ageBaseS_;       // idade acumulada na importacao (holdover)
    bool     ageIsAssumed_;   // a idade veio de uma ASSUMPCAO?
    uint8_t  holdoverOrigin_; // origem original do holdover importado

public:
    HefTimeSource()
        : maxAgeS_(43200UL),        // 12 h
          maxDowntimeS_(900UL),     // 15 min (ver README 9.8.5)
          maxDriftPpm_(500),
          ageBaseS_(0),
          ageIsAssumed_(false),
          holdoverOrigin_(HEF_TIME_NONE) {
        memset(&st_, 0, sizeof(st_));
        st_.source = HEF_TIME_NONE;
    }

    // -------------------------------------------------------------
    // configure
    //
    // `maxAgeS`      = idade maxima do holdover em RUNTIME (a partir
    //                  da ultima sincronizacao). Expirada, a hora
    //                  deixa de ser valida e o TOTP e' recusado.
    // `maxDowntimeS` = downtime MAXIMO assumido apos um power cycle
    //                  sem RTC. Ver a nota sobre o holdover apos
    //                  reinicio.
    // `maxDriftPpm`  = limite da deriva estimada (protege contra
    //                  medicoes absurdas).
    // -------------------------------------------------------------
    void configure(uint32_t maxAgeS, uint32_t maxDowntimeS,
                   int32_t maxDriftPpm) {
        if (maxAgeS > 0) maxAgeS_ = maxAgeS;
        maxDowntimeS_ = maxDowntimeS;
        if (maxDriftPpm > 0) maxDriftPpm_ = maxDriftPpm;
    }

    // -------------------------------------------------------------
    // sync: registra uma sincronizacao externa.
    //
    // `source` = a origem (GNSS, RTC, SNTP, MANUAL).
    // `utc`    = o UTC observado pela fonte.
    // `nowMs`  = millis() no instante da leitura.
    //
    // A sincronizacao tambem REESTIMA a deriva, comparando o UTC
    // observado com o previsto pelo relogio local.
    // -------------------------------------------------------------
    void sync(uint8_t source, uint32_t utc, uint32_t nowMs) {
        // --- Reestimativa da deriva ---
        // So faz sentido se houve uma sincronizacao anterior e se
        // passou tempo suficiente para a medida ter ruido.
        if (st_.haveSync) {
            uint32_t elapsedS = (nowMs - st_.setAtMs) / 1000UL;
            // Menos de 60 s: o erro de arredondamento domina a
            // medida. Nao se mede.
            if (elapsedS >= 60UL) {
                uint32_t predicted = st_.utc + elapsedS;
                int64_t errS = (int64_t)utc - (int64_t)predicted;
                // Erro maior que 5 min: a sincronizacao anterior era
                // velha ou ruim demais para servir de referencia.
                if (errS > -300 && errS < 300) {
                    int64_t ppm = (errS * 1000000LL) / (int64_t)elapsedS;
                    if (ppm > maxDriftPpm_) ppm = maxDriftPpm_;
                    if (ppm < -maxDriftPpm_) ppm = -maxDriftPpm_;
                    st_.driftPpm = (int32_t)ppm;
                }
            }
        }

        st_.source    = source;
        st_.utc       = utc;
        st_.setAtMs   = nowMs;
        st_.haveSync  = true;
        ageBaseS_     = 0;
        ageIsAssumed_ = false;
    }

    // -------------------------------------------------------------
    // Tempo decorrido desde a ultima sincronizacao (segundos).
    // -------------------------------------------------------------
    uint32_t elapsedSeconds(uint32_t nowMs) const {
        return (nowMs - st_.setAtMs) / 1000UL;
    }

    // -------------------------------------------------------------
    // ageSeconds: ha quanto tempo a hora foi CONFIRMADA.
    //
    // Em runtime, e' o tempo desde a ultima sincronizacao.
    // Apos um power cycle (holdover importado da NVS), e' o tempo
    // desde a ultima sincronizacao MAIS o downtime ASSUMIDO — porque
    // o downtime real e' desconhecido.
    // -------------------------------------------------------------
    uint32_t ageSeconds(uint32_t nowMs) const {
        // Sem sincronizacao nao ha idade a reportar: a hora nunca foi
        // confirmada. `valid()` ja e' falso nesse caso.
        if (!st_.haveSync) return 0;
        return ageBaseS_ + elapsedSeconds(nowMs);
    }

    // -------------------------------------------------------------
    // utc: o UTC estimado agora.
    //
    // A extrapolacao usa o relogio local, corrigido pela deriva
    // estimada.
    // -------------------------------------------------------------
    uint32_t utc(uint32_t nowMs) const {
        if (!st_.haveSync) return 0;
        uint32_t elapsedS = elapsedSeconds(nowMs);
        // Correcao de deriva: elapsed * ppm / 1e6.
        // Em 64 bits para nao estourar com elapsed grande.
        int64_t corr = ((int64_t)elapsedS * (int64_t)st_.driftPpm) / 1000000LL;
        int64_t t = (int64_t)st_.utc + (int64_t)elapsedS + corr;
        if (t < 0) return 0;
        if (t > 0xFFFFFFFFLL) return 0xFFFFFFFFUL;
        return (uint32_t)t;
    }

    // -------------------------------------------------------------
    // valid: a hora pode ser usada (inclusive pelo TOTP)?
    //
    // FAIL CLOSED: sem sincronizacao, com idade expirada ou com UTC
    // anterior a 2024, a hora NAO e' valida.
    // -------------------------------------------------------------
    bool valid(uint32_t nowMs) const {
        if (!st_.haveSync) return false;
        if (ageSeconds(nowMs) > maxAgeS_) return false;
        if (utc(nowMs) <= 1704067200UL) return false;   // 01/01/2024
        return true;
    }

    // -------------------------------------------------------------
    // Consultas
    // -------------------------------------------------------------
    uint8_t  source()      const { return st_.source; }
    uint32_t lastUtc()     const { return st_.utc; }
    int32_t  driftPpm()    const { return st_.driftPpm; }
    bool     haveSync()    const { return st_.haveSync; }
    uint32_t maxAgeS()     const { return maxAgeS_; }

    // A idade atual foi ASSUMIDA (holdover apos power cycle) em vez
    // de medida? O operador precisa saber que a hora tem uma
    // incerteza nao medida.
    bool     ageIsAssumed() const { return ageIsAssumed_; }
    uint32_t assumedDowntimeS() const { return ageIsAssumed_ ? ageBaseS_ : 0; }

    // A origem original do holdover importado (GNSS/RTC/SNTP/manual).
    // Util apenas para diagnostico: a origem ATUAL e' `source()`.
    uint8_t  holdoverOrigin() const { return holdoverOrigin_; }

    // -------------------------------------------------------------
    // Serializacao do holdover (NVS)
    //
    // Guarda a ultima hora VALIDA para que ela sobreviva a um
    // reinicio. Ver a nota sobre o downtime assumido.
    // -------------------------------------------------------------
    void exportBlob(uint8_t* out, size_t len) const {
        if (!out || len < HEF_TIME_BLOB_LEN) return;
        memset(out, 0, HEF_TIME_BLOB_LEN);
        out[0] = HEF_TIME_FORMAT_VERSION;
        out[1] = st_.source;
        out[2] = st_.haveSync ? 1 : 0;
        put32(out + 4,  st_.utc);
        put32(out + 8,  st_.setAtMs);
        put32(out + 12, (uint32_t)st_.driftPpm);
        put32(out + 16, ageBaseS_);
    }

    // Importa o holdover.
    //
    // IMPORTANTE: apos um power cycle o tempo de permanencia desligado
    // e' DESCONHECIDO (o relogio local morreu com a alimentacao). Nao
    // ha como saber se o aparelho ficou 1 min ou 3 dias desligado.
    //
    // A solucao adotada e' uma ASSUMPCAO EXPLICITA e LIMITADA
    // (`maxDowntimeS`): a idade e' contada como se o downtime tivesse
    // sido o maximo admissivel. A hora estimada NAO recebe um salto
    // artificial (seria inventar um tempo), mas a IDADE reportada e'
    // conservadora — e `valid()` expira mais cedo do que o necesario,
    // nunca mais tarde.
    //
    // O limite do downtime fica visivel na API (`time_age_assumed`), e
    // o README documenta a limitacao. Quem opera com o aparelho
    // desligado por mais de `maxDowntimeS` precisa de um RTC externo
    // (a solucao preferida do plano) ou de um `settime` manual.
    bool importBlob(const uint8_t* in, size_t len) {
        memset(&st_, 0, sizeof(st_));
        ageBaseS_ = 0;
        ageIsAssumed_ = false;
        holdoverOrigin_ = HEF_TIME_NONE;
        st_.source = HEF_TIME_NONE;

        if (!in || len < HEF_TIME_BLOB_LEN) return false;
        if (in[0] != HEF_TIME_FORMAT_VERSION) return false;

        uint8_t source = in[1];
        bool haveSync = (in[2] != 0);
        uint32_t utc  = get32(in + 4);
        int32_t  ppm  = (int32_t)get32(in + 12);

        // Sanidade: uma hora absurda e' lixo de NVS, nao um holdover.
        if (!haveSync || utc <= 1704067200UL) return false;
        if (ppm > maxDriftPpm_ || ppm < -maxDriftPpm_) return false;

        // A origem original (GNSS/RTC/SNTP/manual) e' preservada para
        // diagnostico: o operador precisa saber de onde veio a hora
        // extrapolada ("holdover de gnss" e' informacao diferente de
        // "holdover de sntp").
        holdoverOrigin_ = source;

        st_.source      = HEF_TIME_HOLDOVER;
        st_.utc         = utc;
        st_.setAtMs     = 0;          // o relogio local reiniciou
        st_.driftPpm    = ppm;
        st_.haveSync    = true;
        ageBaseS_       = maxDowntimeS_;
        ageIsAssumed_   = true;
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

#endif // HEF_TIME_SOURCE_H
