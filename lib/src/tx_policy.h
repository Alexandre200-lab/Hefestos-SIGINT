// tx_policy.h - Politica de transmissao adaptativa do Node 1 - v5.1.0
//
// OBJETIVO
//   A v5.0.0 (e a v5.1.0 ate o item 1.3) transmitia PERIODICAMENTE: um
//   frame a cada 30 s, independente de o alvo ter se movido ou nao.
//
//   Numa frota militar isso e' desperdicio duplo:
//     - de espectro (cada frame ocupa 329 ms de tempo no ar);
//     - de energia (o RX do SX1276 fica ligado a espera do ACK).
//
//   A politica adaptativa transmite por EVENTO:
//     - a posicao alterou mais que `LORA_MIN_MOVE_M`; OU
//     - passou `LORA_HEARTBEAT_TX_MS` desde a ultima transmissao
//       (heartbeat: a base precisa saber que o no esta vivo).
//
//   O heartbeat e' essencial: sem ele, um alvo parado seria indistinguivel
//   de um alvo que saiu de campo (ou teve a bateria drenada).
//
// REGRAS
//   1. O intervalo MINIMO entre duas transmissoes e' sempre respeitado
//      (`LORA_TX_INTERVAL_MIN_MS`, derivado do duty cycle do perfil).
//      Sem isso, um alvo em movimento perpetuo inundaria o enlace.
//   2. O jitter (+/- LORA_TX_JITTER_PCT) e' aplicado ao intervalo
//      efetivo, para dessincronizar a frota.
//   3. Sem fix GNSS valido, so o heartbeat dispara: e' importante que a
//      base saiba que o no esta online MESMO sem posicao.
//
// BEACON FM
//   O beacon FM (Si4713) e' um transmissor INDEPENDENTE do link LoRa:
//   tem o proprio duty cycle e o proprio corte por bateria. Um beacon que
//   drena a bateria do no e' pior que nenhum beacon.
//
// Este modulo e' C++ puro (sem Arduino/ESP) para ser testado no HOST
// (tests/tx_policy.cpp).
#ifndef HEF_TX_POLICY_H
#define HEF_TX_POLICY_H

#include <stdint.h>
#include <math.h>

// ---------------------------------------------------------------------
// Distancia (Haversine)
// ---------------------------------------------------------------------
// Retorna a distancia em metros entre dois pontos. Raio da Terra:
// 6371008,8 m (media terrestre, IUGG). A formula e' numericamente
// estavel para as distâncias curtas que interessam a um alvo (m a km).
inline double hefHaversineMeters(double lat1, double lon1,
                                 double lat2, double lon2) {
    static const double kEarthRadiusM = 6371008.8;
    static const double kDegToRad = 0.017453292519943295;

    double phi1 = lat1 * kDegToRad;
    double phi2 = lat2 * kDegToRad;
    double dPhi = (lat2 - lat1) * kDegToRad;
    double dLam = (lon2 - lon1) * kDegToRad;

    double sinPhi = sin(dPhi * 0.5);
    double sinLam = sin(dLam * 0.5);
    double a = sinPhi * sinPhi +
               cos(phi1) * cos(phi2) * sinLam * sinLam;
    if (a < 0.0) a = 0.0;
    if (a > 1.0) a = 1.0;
    double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
    return kEarthRadiusM * c;
}

// ---------------------------------------------------------------------
// Politica de transmissao do link LoRa
// ---------------------------------------------------------------------
enum HefTxTrigger {
    HEF_TX_TRIGGER_NONE = 0,   // nada a fazer
    HEF_TX_TRIGGER_MOVE,       // o alvo se moveu acima do limiar
    HEF_TX_TRIGGER_HEARTBEAT   // heartbeat (ou primeiro contato)
};

class HefTxPolicy {
public:
    // Fonte de aleatoriedade injetada. No firmware: esp_random(). No
    // host: um LCG deterministico, para que o teste seja reproduzivel.
    typedef uint32_t (*RandFn)();

private:
    // --- configuracao ---
    double   minMoveM_;       // limiar de movimento (m)
    uint32_t heartbeatMs_;    // intervalo maximo sem transmitir (ms)
    uint32_t minIntervalMs_;  // piso entre duas transmissoes (ms)
    uint32_t jitterPct_;      // dispersao do piso (+/- %)
    RandFn   randFn_;         // fonte de aleatoriedade (pode ser nula)

    // --- estado ---
    bool     refValid_;       // a referencia de posicao e' valida?
    bool     haveLastTx_;
    double   lastLat_;        // referencia de posicao (ultima REPORTADA)
    double   lastLon_;
    uint32_t lastTxMs_;
    uint32_t nextAllowedMs_;  // instante do proximo TX permitido (com jitter)
    bool     pendingMove_;    // movimento detectado e AINDA NAO reportado
    double   lastDistanceM_;
    uint32_t events_;         // eventos (movimento) detectados
    uint32_t heartbeats_;      // heartbeats disparados

public:
    HefTxPolicy()
        : minMoveM_(10.0), heartbeatMs_(60000UL), minIntervalMs_(30000UL),
          jitterPct_(0), randFn_(nullptr),
          refValid_(false), haveLastTx_(false),
          lastLat_(0.0), lastLon_(0.0), lastTxMs_(0), nextAllowedMs_(0),
          pendingMove_(false),
          lastDistanceM_(0.0), events_(0), heartbeats_(0) {}

    void configure(double minMoveM, uint32_t heartbeatMs, uint32_t minIntervalMs) {
        if (minMoveM < 0.0) minMoveM = 0.0;
        minMoveM_       = minMoveM;
        heartbeatMs_    = heartbeatMs;
        minIntervalMs_  = minIntervalMs;
    }

    // Dispersao do piso de intervalo (+/- pct). E' o que dessincroniza
    // a frota: varias unidades que acordam juntas nao colidem.
    void setJitterPct(uint32_t pct) { jitterPct_ = pct; }
    void setRandomSource(RandFn fn) { randFn_ = fn; }

    double   minMoveM()      const { return minMoveM_; }
    uint32_t heartbeatMs()   const { return heartbeatMs_; }
    uint32_t minIntervalMs() const { return minIntervalMs_; }
    uint32_t jitterPct()     const { return jitterPct_; }

    uint32_t events()    const { return events_; }
    uint32_t heartbeats() const { return heartbeats_; }
    double   lastDistanceM() const { return lastDistanceM_; }
    bool     hasLastTx() const { return haveLastTx_; }
    uint32_t lastTxMs()  const { return lastTxMs_; }
    uint32_t nextAllowedMs() const { return nextAllowedMs_; }
    bool     hasPendingMove() const { return pendingMove_; }

    // -------------------------------------------------------------
    // evaluate: o que deve ser feito agora?
    //
    // `fixValid` false = sem posicao confiavel (o no so pode reportar
    // heartbeat; um "movimento" nao pode ser estimado).
    //
    // SEMANTICA DA REFERENCIA
    //   A referencia de posicao e' a do ULTIMO frame REPORTADO com
    //   sucesso, nao a da ultima posicao observada. Consequencia
    //   direta: se uma transmissao for negada (duty cycle, erro), o
    //   movimento NAO e' perdido — ele continua pendente e sera
    //   reportado na proxima oportunidade.
    //
    //   A distancia e' comparada contra a referencia reportada, e o
    //   limiar e' `minMoveM_`.
    //
    // ORDEM DELIBERADA
    //   1. Piso de intervalo: mesmo um movimento grande nao pode
    //      violar o piso — o enlace e' um recurso compartilhado.
    //      O piso ja' vem com o jitter aplicado.
    //   2. Primeiro contato: a base precisa saber que o no existe.
    //   3. Movimento pendente.
    //   4. Heartbeat.
    // -------------------------------------------------------------
    HefTxTrigger evaluate(uint32_t nowMs, bool fixValid, double lat, double lon) {
        // --- piso de intervalo (duty cycle / anti-sincronismo) ---
        // O piso vale MESMO antes do primeiro contato: se a primeira
        // transmissao for negada, `onTxFailed()` reprograma o piso e
        // impede que o loop principal re-tente milhares de vezes por
        // segundo.
        if (nowMs < nextAllowedMs_) {
            return HEF_TX_TRIGGER_NONE;
        }

        // --- primeiro contato ---
        if (!haveLastTx_) return HEF_TX_TRIGGER_HEARTBEAT;

        // --- posicao: referencia e deteccao de movimento ---
        if (fixValid) {
            if (!refValid_) {
                // A base ainda nao recebeu UMA posicao valida deste no.
                // Isso e' uma mudanca de estado relevante: o evento e'
                // disparado para reportar a primeira posicao.
                pendingMove_ = true;
                lastDistanceM_ = 0.0;
            } else {
                double d = hefHaversineMeters(lastLat_, lastLon_, lat, lon);
                lastDistanceM_ = d;
                if (d > minMoveM_) pendingMove_ = true;
            }
        }

        // --- movimento pendente (ainda nao reportado) ---
        if (pendingMove_) return HEF_TX_TRIGGER_MOVE;

        // --- heartbeat ---
        if ((nowMs - lastTxMs_) >= heartbeatMs_) return HEF_TX_TRIGGER_HEARTBEAT;

        return HEF_TX_TRIGGER_NONE;
    }

    // -------------------------------------------------------------
    // onTransmitted: confirma que o frame saiu. Atualiza o estado.
    //
    // E' aqui que o jitter do piso e' sorteado: o proximo TX podera
    // ocorrer entre minIntervalMs_*(1-p) e minIntervalMs_*(1+p).
    // -------------------------------------------------------------
    void onTransmitted(uint32_t nowMs, bool fixValid, double lat, double lon) {
        lastTxMs_ = nowMs;
        haveLastTx_ = true;
        nextAllowedMs_ = nowMs + jitteredIntervalMs();
        pendingMove_ = false;   // o movimento foi reportado
        if (fixValid) {
            lastLat_ = lat;
            lastLon_ = lon;
            refValid_ = true;    // a referencia passa a ser a posicao reportada
        } else {
            // O frame saiu SEM posicao. A referencia de posicao fica
            // invalida: a proxima posicao valida sera tratada como
            // "primeira posicao" e reportada imediatamente.
            refValid_ = false;
        }
    }

    // -------------------------------------------------------------
    // onTxFailed: a transmissao NAO saiu (duty cycle, erro de
    // cifragem, etc).
    //
    // O movimento PENDENTE e' PRESERVADO: o evento nao e' perdido. Mas
    // o piso de intervalo e' reprogramado, para que a proxima
    // tentativa nao vire um flood (o loop principal chama evaluate()
    // milhares de vezes por segundo).
    // -------------------------------------------------------------
    void onTxFailed(uint32_t nowMs) {
        nextAllowedMs_ = nowMs + jitteredIntervalMs();
    }

    // Piso de intervalo com jitter aplicado: minIntervalMs_ +/- jitterPct_%.
    uint32_t jitteredIntervalMs() const {
        if (jitterPct_ == 0 || randFn_ == nullptr) return minIntervalMs_;
        int32_t span = (int32_t)((uint32_t)minIntervalMs_ * jitterPct_ / 100UL);
        if (span <= 0) return minIntervalMs_;
        uint32_t r = randFn_() % (uint32_t)(2 * span + 1);
        int32_t v = (int32_t)minIntervalMs_ + ((int32_t)r - span);
        if (v < 1000) v = 1000;
        return (uint32_t)v;
    }

    // Registra um disparo (para diagnostico). Nao altera a decisao.
    void noteTrigger(HefTxTrigger t) {
        if (t == HEF_TX_TRIGGER_MOVE) events_++;
        else if (t == HEF_TX_TRIGGER_HEARTBEAT) heartbeats_++;
    }

    void reset() {
        refValid_ = false;
        haveLastTx_ = false;
        lastLat_ = lastLon_ = 0.0;
        lastTxMs_ = 0;
        nextAllowedMs_ = 0;
        pendingMove_ = false;
        lastDistanceM_ = 0.0;
        events_ = heartbeats_ = 0;
    }
};

// ---------------------------------------------------------------------
// Politica do beacon FM (Si4713)
// ---------------------------------------------------------------------
enum HefBeaconAction {
    HEF_BEACON_NONE = 0,   // nada a fazer
    HEF_BEACON_ON,         // ligar o beacon
    HEF_BEACON_OFF         // desligar o beacon
};

// O beacon e' um transmissor COM CONTINUO: o consumo e' da ordem de
// dezenas de mA enquanto ele esta em ON. O duty cycle proprio (ON/OFF)
// e' o que torna o beacon viavel em bateria.
//
// O corte por bateria e' automatico e NAO NEGOCIAVEL: abaixo do limiar
// o beacon e' desligado, porque preservar a telemetria LoRa (que e' o
// que mantem a base ciente da unidade) tem prioridade sobre um beacon
// audivel.
class HefBeaconPolicy {
private:
    uint32_t onMs_;
    uint32_t offMs_;
    uint8_t  minBatteryPct_;
    bool     beaconOn_;
    bool     poweredOff_;   // desligado por bateria (trava ate rearmar)
    uint32_t phaseStartMs_;
    uint32_t offCount_;
    uint32_t onCount_;

public:
    HefBeaconPolicy()
        : onMs_(3000UL), offMs_(27000UL), minBatteryPct_(20),
          beaconOn_(false), poweredOff_(false),
          phaseStartMs_(0), offCount_(0), onCount_(0) {}

    void configure(uint32_t onMs, uint32_t offMs, uint8_t minBatteryPct) {
        onMs_ = onMs;
        offMs_ = offMs;
        minBatteryPct_ = minBatteryPct;
    }

    uint32_t onMs()            const { return onMs_; }
    uint32_t offMs()           const { return offMs_; }
    uint8_t  minBatteryPct()   const { return minBatteryPct_; }
    bool     isOn()            const { return beaconOn_; }
    bool     isPoweredOff()    const { return poweredOff_; }
    uint32_t offCount()        const { return offCount_; }
    uint32_t onCount()         const { return onCount_; }

    // Duty cycle nominal do beacon (%).
    float dutyPercent() const {
        uint32_t total = onMs_ + offMs_;
        if (total == 0) return 0.0f;
        return (100.0f * (float)onMs_) / (float)total;
    }

    // -------------------------------------------------------------
    // evaluate: decide a acao do beacon.
    //
    // `enabled`     = o operador ligou o beacon (`fm on`)
    // `batteryPct`  = 255 = desconhecido (nao aplica o corte)
    // `nowMs`       = relogio monotonico
    // -------------------------------------------------------------
    HefBeaconAction evaluate(uint32_t nowMs, bool enabled, uint8_t batteryPct) {
        // --- corte por bateria ---
        if (batteryPct != 255 && batteryPct < minBatteryPct_) {
            poweredOff_ = true;
        }

        // --- desligado: nao ha nada a fazer alem de garantir o OFF ---
        if (!enabled || poweredOff_) {
            if (beaconOn_) {
                beaconOn_ = false;
                offCount_++;
                return HEF_BEACON_OFF;
            }
            return HEF_BEACON_NONE;
        }

        // --- fase ON ---
        if (!beaconOn_) {
            uint32_t elapsed = nowMs - phaseStartMs_;
            if (phaseStartMs_ == 0 || elapsed >= offMs_) {
                beaconOn_ = true;
                onCount_++;
                phaseStartMs_ = nowMs;
                return HEF_BEACON_ON;
            }
            return HEF_BEACON_NONE;
        }

        // --- fase OFF ---
        if ((nowMs - phaseStartMs_) >= onMs_) {
            beaconOn_ = false;
            offCount_++;
            return HEF_BEACON_OFF;
        }
        return HEF_BEACON_NONE;
    }

    // Rearma o corte por bateria (o operador recarregou a unidade).
    void rearm() {
        poweredOff_ = false;
        phaseStartMs_ = 0;
    }

    void reset() {
        beaconOn_ = false;
        poweredOff_ = false;
        phaseStartMs_ = 0;
        offCount_ = 0;
        onCount_ = 0;
    }
};

#endif // HEF_TX_POLICY_H
