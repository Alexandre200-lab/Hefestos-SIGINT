// radio_si4735.h - Wrapper do receptor Si4735 (PU2CLR/SI4735) - v5.0.0
//
// CORRECOES (v4.x):
//   - readRSSI() lia LoRa.packetRssi() e era usado na varredura de banda.
//     Ou seja, a "tabela de espectro" reportava o RSSI do LORA para todas
//     as bandas/frequencias. Agora usa a API real do Si4735
//     (getCurrentReceivedSignalQuality() -> RSSI/SNR do receptor).
//   - A v4.x chamava um metodo inexistente, setBand(const char*, float).
//   - Cada troca de banda na v4.x fazia power-down/power-up completo do
//     chip (setFM()/setAM() fazem isso internamente). Agora a mudanca de
//     banda e' feita uma vez e o stepping dentro da banda usa
//     setFrequency(), que NAO reinicia o chip.
//   - A varredura nao restaurava a frequencia do operador ao final.
#ifndef HEF_RADIO_SI4735_H
#define HEF_RADIO_SI4735_H

#include <Arduino.h>
#include <SI4735.h>

#include "hefestos_pins.h"

enum HefBand {
    HEF_BAND_NONE = 0,
    HEF_BAND_FM,
    HEF_BAND_AM,
    HEF_BAND_SW
};

struct HefSignalQuality {
    bool    valid;
    uint8_t rssiDBuV;   // 0..127 dBuV
    uint8_t snrDb;      // 0..127 dB
    uint8_t multipath;  // 0..100
};

class HefRadio {
private:
    SI4735& radio_;
    HefBand currentBand_;
    uint32_t currentFreqKHz_;
    bool    initialized_;

    static HefBand bandFromName(const char* name) {
        if (!name) return HEF_BAND_NONE;
        if (strcmp(name, "FM") == 0) return HEF_BAND_FM;
        if (strcmp(name, "AM") == 0) return HEF_BAND_AM;
        if (strcmp(name, "SW") == 0) return HEF_BAND_SW;
        return HEF_BAND_NONE;
    }

public:
    explicit HefRadio(SI4735& radio) : radio_(radio), currentBand_(HEF_BAND_NONE),
                                       currentFreqKHz_(0), initialized_(false) {}

    bool begin(uint8_t resetPin) {
        radio_.setup(resetPin, POWER_UP_FM);
        radio_.setFM(8750, 10800, 10010, 10);   // 87.5..108.0 MHz, passo 100 kHz
        radio_.setVolume(40);
        currentBand_ = HEF_BAND_FM;
        currentFreqKHz_ = 100100;
        initialized_ = true;
        return true;
    }

    bool isInitialized() const { return initialized_; }
    HefBand band() const { return currentBand_; }
    uint32_t freqKHz() const { return currentFreqKHz_; }

    static const char* bandName(HefBand b) {
        switch (b) {
            case HEF_BAND_FM: return "FM";
            case HEF_BAND_AM: return "AM";
            case HEF_BAND_SW: return "SW";
            default:          return "NONE";
        }
    }

    // Sintoniza em kHz. Retorna false se a frequencia estiver fora da banda.
    bool tune(HefBand band, uint32_t freqKHz) {
        if (!initialized_) return false;

        if (band == HEF_BAND_FM) {
            if (freqKHz < 87500 || freqKHz > 108000) return false;
            if (currentBand_ != HEF_BAND_FM) {
                radio_.setFM(8750, 10800, (uint16_t)(freqKHz / 10), 10);
            } else {
                radio_.setFrequency((uint16_t)(freqKHz / 10));
            }
            currentBand_ = HEF_BAND_FM;
        } else if (band == HEF_BAND_AM) {
            if (freqKHz < 520 || freqKHz > 1710) return false;
            if (currentBand_ != HEF_BAND_AM) {
                radio_.setAM(520, 1710, (uint16_t)freqKHz, 10);
            } else {
                radio_.setFrequency((uint16_t)freqKHz);
            }
            currentBand_ = HEF_BAND_AM;
        } else if (band == HEF_BAND_SW) {
            if (freqKHz < 2300 || freqKHz > 30000) return false;
            if (currentBand_ != HEF_BAND_SW) {
                radio_.setAM(2300, 30000, (uint16_t)freqKHz, 5);
            } else {
                radio_.setFrequency((uint16_t)freqKHz);
            }
            currentBand_ = HEF_BAND_SW;
        } else {
            return false;
        }
        currentFreqKHz_ = freqKHz;
        return true;
    }

    // Sintoniza por nome de banda + kHz (usado pela CLI/HTTP).
    bool tuneByName(const char* bandName, uint32_t freqKHz) {
        return tune(bandFromName(bandName), freqKHz);
    }

    // Le a qualidade do sinal do proprio receptor (NAO do LoRa).
    HefSignalQuality readQuality() {
        HefSignalQuality q;
        q.valid = false;
        q.rssiDBuV = 0;
        q.snrDb = 0;
        q.multipath = 0;
        if (!initialized_) return q;
        radio_.getCurrentReceivedSignalQuality();
        q.rssiDBuV = radio_.getCurrentRSSI();
        q.snrDb    = radio_.getCurrentSNR();
        q.valid    = (q.rssiDBuV > 0);
        return q;
    }
};

#endif // HEF_RADIO_SI4735_H
