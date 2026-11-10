// spectrum.h - Varredura de espectro NAO-BLOQUEANTE - v5.0.0
//
// A v4.x executava a varredura de forma sincrona dentro de loop(), com
// delay(50) entre os pontos. Como setFM()/setAM() reiniciam o chip
// (power-down + power-up), o receptor ficava fora do ar a maior parte do
// ciclo e a frequencia do operador nunca era restaurada.
//
// v5:
//   - Maquina de estados sem delay: tick() e' chamado do loop e avanca um
//     passo por vez, respeitando o dwell time.
//   - O stepping dentro da banda usa setFrequency() (nao reinicia o chip).
//   - A frequencia do operador e' restaurada ao final da varredura.
//   - Os pontos ficam num ring buffer consultavel pela API HTTP.
#ifndef HEF_SPECTRUM_H
#define HEF_SPECTRUM_H

#include <Arduino.h>

#include "hefestos_pins.h"
#include "radio_si4735.h"

struct SpectrumPoint {
    uint8_t  band;        // HefBand
    uint32_t freqKHz;
    uint8_t  rssiDBuV;
    uint8_t  snrDb;
    bool     valid;
    uint32_t timestampMs;
};

struct SpectrumPlan {
    uint8_t  band;
    uint32_t startKHz;
    uint32_t stopKHz;
    uint32_t stepKHz;
};

class SpectrumScanner {
private:
    HefRadio& radio_;
    SpectrumPlan plan_[6];
    uint8_t     planCount_;
    bool        running_;
    uint8_t     planIndex_;
    uint32_t    nextFreqKHz_;
    uint32_t    settleUntilMs_;
    uint32_t    dwellMs_;

    SpectrumPoint samples_[SPECTRUM_RING];
    uint16_t     sampleHead_;
    uint16_t     sampleCount_;
    uint32_t     lastSweepMs_;

    // Estado do operador restaurado ao final da varredura
    HefBand  restoreBand_;
    uint32_t restoreFreqKHz_;

public:
    explicit SpectrumScanner(HefRadio& radio)
        : radio_(radio), planCount_(0), running_(false), planIndex_(0),
          nextFreqKHz_(0), settleUntilMs_(0), dwellMs_(SWEEP_DWELL_MS),
          sampleHead_(0), sampleCount_(0), lastSweepMs_(0),
          restoreBand_(HEF_BAND_NONE), restoreFreqKHz_(0) {}

    void setDwell(uint32_t ms) { dwellMs_ = ms < 20 ? 20 : ms; }

    // Define o plano de varredura. Retorna o numero de bandas aceitas.
    uint8_t setPlan(const SpectrumPlan* plans, uint8_t count) {
        planCount_ = 0;
        for (uint8_t i = 0; i < count && i < 6; i++) {
            if (plans[i].stepKHz == 0) continue;
            if (plans[i].stopKHz <= plans[i].startKHz) continue;
            plan_[planCount_++] = plans[i];
        }
        return planCount_;
    }

    // Plano padrao: FM 87.5-108 MHz (passo 250 kHz), AM 520-1710 kHz
    // (passo 20 kHz), SW 2.3-30 MHz (passo 25 kHz).
    void setDefaultPlan() {
        SpectrumPlan p[3];
        p[0].band = HEF_BAND_FM; p[0].startKHz = 87500; p[0].stopKHz = 108000; p[0].stepKHz = 250;
        p[1].band = HEF_BAND_AM; p[1].startKHz = 520;   p[1].stopKHz = 1710;   p[1].stepKHz = 20;
        p[2].band = HEF_BAND_SW; p[2].startKHz = 2300;  p[2].stopKHz = 30000;  p[2].stepKHz = 25;
        setPlan(p, 3);
    }

    bool isRunning() const { return running_; }

    void start() {
        if (!radio_.isInitialized() || planCount_ == 0) return;
        restoreBand_  = radio_.band();
        restoreFreqKHz_ = radio_.freqKHz();
        running_ = true;
        planIndex_ = 0;
        nextFreqKHz_ = plan_[0].startKHz;
        radio_.tune((HefBand)plan_[0].band, nextFreqKHz_);
        settleUntilMs_ = millis() + SI4735_SETTLE_MS;
    }

    void stop() {
        if (!running_) return;
        running_ = false;
        // Restaura a sintonia do operador.
        if (restoreBand_ != HEF_BAND_NONE) {
            radio_.tune(restoreBand_, restoreFreqKHz_);
        }
    }

    // Avanca a varredura em um passo por chamada. Nao bloqueia.
    // Retorna true quando um novo ponto foi medido e registrado.
    bool tick(uint32_t now) {
        if (!running_) return false;

        // Ainda esperando o chip assentar na frequencia atual.
        if (now < settleUntilMs_) return false;

        // 1) Mede o ponto atual.
        HefSignalQuality q = radio_.readQuality();
        SpectrumPoint pt;
        pt.band        = radio_.band();
        pt.freqKHz     = radio_.freqKHz();
        pt.rssiDBuV    = q.rssiDBuV;
        pt.snrDb       = q.snrDb;
        pt.valid       = q.valid;
        pt.timestampMs = now;

        samples_[sampleHead_] = pt;
        sampleHead_ = (uint16_t)((sampleHead_ + 1) % SPECTRUM_RING);
        if (sampleCount_ < SPECTRUM_RING) sampleCount_++;

        // 2) Avanca para o proximo ponto do plano.
        const SpectrumPlan& p = plan_[planIndex_];
        uint32_t nextFreq = nextFreqKHz_ + p.stepKHz;
        if (nextFreq > p.stopKHz) {
            planIndex_++;
            if (planIndex_ >= planCount_) {
                running_ = false;
                lastSweepMs_ = now;
                if (restoreBand_ != HEF_BAND_NONE) {
                    radio_.tune(restoreBand_, restoreFreqKHz_);
                }
                return true;
            }
            nextFreq = plan_[planIndex_].startKHz;
        }
        nextFreqKHz_ = nextFreq;
        radio_.tune((HefBand)plan_[planIndex_].band, nextFreq);
        settleUntilMs_ = now + dwellMs_ + SI4735_SETTLE_MS;
        return true;
    }

    uint16_t sampleCount() const { return sampleCount_; }

    // Le a amostra mais recente (indice 0 = mais recente).
    bool latest(SpectrumPoint* out) const {
        if (sampleCount_ == 0 || !out) return false;
        uint16_t idx = (sampleHead_ + SPECTRUM_RING - 1) % SPECTRUM_RING;
        *out = samples_[idx];
        return true;
    }

    // Le a amostra mais recente dentro de uma banda.
    bool latestForBand(HefBand band, SpectrumPoint* out) const {
        if (sampleCount_ == 0 || !out) return false;
        for (uint16_t i = 0; i < sampleCount_; i++) {
            uint16_t idx = (sampleHead_ + SPECTRUM_RING - 1 - i) % SPECTRUM_RING;
            if (samples_[idx].band == band) { *out = samples_[idx]; return true; }
        }
        return false;
    }

    // Acessa uma amostra por idade (0 = mais recente).
    bool atAge(uint16_t age, SpectrumPoint* out) const {
        if (age >= sampleCount_ || !out) return false;
        uint16_t idx = (uint16_t)((sampleHead_ + SPECTRUM_RING - 1 - age) % SPECTRUM_RING);
        *out = samples_[idx];
        return true;
    }

    void clearSamples() { sampleHead_ = 0; sampleCount_ = 0; }
    uint32_t lastSweepMs() const { return lastSweepMs_; }
};

#endif // HEF_SPECTRUM_H
