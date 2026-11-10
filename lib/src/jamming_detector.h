// jamming_detector.h - Deteccao real de interferencia/jamming - v5.0.0
//
// A v4.x tinha uma funcao "monitorLinkQuality()" que lia
// secProto.getRXCounter() -> rx_counter, campo que so era atualizado por
// markCounter(), funcao que NUNCA era chamada no projeto. Resultado:
// rx_counter ficava no seed para sempre e o endpoint /jamming respondia
// "NORMAL" SEMPRE. A feature era decorativa.
//
// v5: deteccao baseada em metricas REAIS de RF:
//   - RSSI/SNR dos pacotes LoRa recebidos (margem de enlace)
//   - Piso de ruido do receptor Si4735 (leitura do proprio RF)
//   - Perda de enlace (silencio absoluto do link)
//   - Subida brusca do piso de ruido (interferencia de banda larga)
//
// Estados distintos para nao confundir "jamming" com "alvo longe" ou
// "link naturalmente ruim".
#ifndef HEF_JAMMING_DETECTOR_H
#define HEF_JAMMING_DETECTOR_H

#include <Arduino.h>

#include "hefestos_pins.h"

enum JammingState {
    JF_CLEAR = 0,        // enlace saudavel
    JF_DEGRADED,         // enlace ativo mas com margem baixa
    JF_NOISE_RISE,       // piso de ruido subiu (interferencia de banda larga)
    JF_LINK_LOSS         // nenhum pacote ha N segundos
};

class JammingDetector {
private:
    static const uint8_t WINDOW = 32;

    int16_t rssiWindow_[WINDOW];
    float   snrWindow_[WINDOW];
    uint8_t head_;
    uint8_t count_;

    float   baselineSnr_;      // EMA lenta da margem saudavel
    float   noiseFloorDbuV_;   // EMA lenta do piso de ruido do receptor
    float   lastNoiseDbuV_;    // ultima leitura instantanea
    uint32_t noiseSpikeMs_;    // quando o piso subiu acima do baseline
    bool    noisePrimed_;
    bool    primed_;

    uint32_t lastPacketMs_;
    uint32_t packetsSeen_;
    uint32_t alerts_;

    uint32_t linkLossTimeoutMs_;
    float    degradedSnrDb_;
    float    noiseRiseDb_;

    static float medianOf(const float* vals, uint8_t n) {
        if (n == 0) return 0.0f;
        float tmp[WINDOW];
        for (uint8_t i = 0; i < n; i++) tmp[i] = vals[i];
        for (uint8_t i = 1; i < n; i++) {
            float key = tmp[i];
            uint8_t j = i;
            while (j > 0 && tmp[j - 1] > key) { tmp[j] = tmp[j - 1]; j--; }
            tmp[j] = key;
        }
        return (n % 2) ? tmp[n / 2] : (tmp[n / 2 - 1] + tmp[n / 2]) * 0.5f;
    }

public:
    JammingDetector()
        : head_(0), count_(0), baselineSnr_(0.0f), noiseFloorDbuV_(0.0f),
          lastNoiseDbuV_(0.0f), noiseSpikeMs_(0), noisePrimed_(false),
          primed_(false), lastPacketMs_(0), packetsSeen_(0), alerts_(0),
          linkLossTimeoutMs_(15000UL), degradedSnrDb_(3.0f), noiseRiseDb_(10.0f) {
        memset(rssiWindow_, 0, sizeof(rssiWindow_));
        memset(snrWindow_, 0, sizeof(snrWindow_));
    }

    void configure(uint32_t lossTimeoutMs, float degradedSnr, float noiseRise) {
        if (lossTimeoutMs > 0)     linkLossTimeoutMs_ = lossTimeoutMs;
        if (degradedSnr > 0.0f)    degradedSnrDb_ = degradedSnr;
        if (noiseRise > 0.0f)      noiseRiseDb_ = noiseRise;
    }

    // Registra um pacote LoRa recebido.
    void onPacket(int16_t rssiDbm, float snrDb, uint32_t now) {
        rssiWindow_[head_] = rssiDbm;
        snrWindow_[head_]  = snrDb;
        head_ = (uint8_t)((head_ + 1) % WINDOW);
        if (count_ < WINDOW) count_++;

        lastPacketMs_ = now;
        packetsSeen_++;

        if (!primed_) {
            baselineSnr_ = snrDb;
            primed_ = true;
        } else {
            // EMA lenta: o baseline so "decai" devagar para acompanhar
            // mudancas reais do ambiente sem seguir picos transitorios.
            baselineSnr_ = baselineSnr_ * 0.995f + snrDb * 0.005f;
        }
    }

    // Registra o piso de ruido medido pelo receptor Si4735 (dBuV).
    //
    // O baseline (EMA lenta) so acompanha leituras NORMAIS. Um salto
    // acima de noiseRiseDb_ e' tratado como interferencia e NAO contamina
    // o baseline (senao o detector "se acostumaria" com o jammer).
    void onNoiseFloor(float rssiDbuV, uint32_t now) {
        if (rssiDbuV <= 0.0f) return;
        lastNoiseDbuV_ = rssiDbuV;
        if (!noisePrimed_) {
            noiseFloorDbuV_ = rssiDbuV;
            noisePrimed_ = true;
            return;
        }
        if (rssiDbuV - noiseFloorDbuV_ > noiseRiseDb_) {
            noiseSpikeMs_ = now;
            return;
        }
        noiseFloorDbuV_ = noiseFloorDbuV_ * 0.98f + rssiDbuV * 0.02f;
    }

    void tick(uint32_t now) {
        if (packetsSeen_ == 0) return;
        if (lastPacketMs_ != 0 && (now - lastPacketMs_) > linkLossTimeoutMs_) {
            // nada mais a fazer aqui: state() calcula o caso de perda
        }
    }

    JammingState state(uint32_t now) const {
        if (packetsSeen_ == 0) return JF_CLEAR;   // sem trafego ainda: sem juizo
        if (lastPacketMs_ != 0 && (now - lastPacketMs_) > linkLossTimeoutMs_) {
            return JF_LINK_LOSS;
        }
        // Subida do piso de ruido do receptor RF (dBuV), com janela de
        // 30 s para nao reportar um pico isolado como jamming.
        if (noiseSpikeMs_ != 0 && (now - noiseSpikeMs_) < 30000UL) {
            return JF_NOISE_RISE;
        }
        // Margem de enlace degradada
        if (count_ > 0) {
            float snrMed = medianOf(snrWindow_, count_);
            if (snrMed < degradedSnrDb_) return JF_DEGRADED;
        }
        return JF_CLEAR;
    }

    static const char* stateName(JammingState s) {
        switch (s) {
            case JF_CLEAR:      return "NORMAL";
            case JF_DEGRADED:   return "DEGRADED";
            case JF_NOISE_RISE: return "NOISE_RISE";
            case JF_LINK_LOSS:  return "LINK_LOSS";
            default:            return "UNKNOWN";
        }
    }

    float medianSnr() const { return count_ ? medianOf(snrWindow_, count_) : 0.0f; }
    float medianRssiDbm() const {
        if (!count_) return 0.0f;
        float tmp[WINDOW];
        for (uint8_t i = 0; i < count_; i++) tmp[i] = (float)rssiWindow_[i];
        return medianOf(tmp, count_);
    }
    float baselineSnr() const { return baselineSnr_; }
    float noiseFloorDbuV() const { return noiseFloorDbuV_; }
    float lastNoiseDbuV() const { return lastNoiseDbuV_; }
    uint32_t packetsSeen() const { return packetsSeen_; }
    uint32_t lastPacketAgeMs(uint32_t now) const {
        return lastPacketMs_ == 0 ? 0 : (now - lastPacketMs_);
    }
    void noteAlert() { alerts_++; }
    uint32_t alerts() const { return alerts_; }
};

#endif // HEF_JAMMING_DETECTOR_H
