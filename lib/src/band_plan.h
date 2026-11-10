// band_plan.h - Perfis de banda por regiao - v5.1.0
//
// OBJETIVO
//   O firmware operava em 915 MHz com SF10 sem nenhuma verificacao de
//   conformidade: qualquer mudanca de parametros de RF era silenciosa.
//
//   Este modulo define PERFIS DE REFERENCIA por regiao, com:
//     - faixa de frequencia admitida;
//     - SF/BW/CR padrao;
//     - limite de EIRP;
//     - orcamento de duty cycle (que o firmware IMPEDE de violar).
//
// AVISO IMPORTANTE
//   Estes valores sao REFERENCIA de engenharia, nao parecer juridico.
//   Os limites regulatorios variam por pais, por sub-banda, por
//   modalidade de acesso (FHSS, DSSS, LPD/CHIP) e por classe de
//   equipamento. O operador DEVE confirmar o perfil aplicavel e os
//   limites vigentes na sua jurisdicao (ANATEL, FCC, ETSI) ANTES de
//   operar. Os limites de duty cycle aqui adotados sao deliberadamente
//   CONSERVADORES (auto-impostos) quando a norma nao fixa um valor.
//
//   Este projeto e' passivo/defensivo: mede o proprio espectro e a
//   propria telemetria.
#ifndef HEF_BAND_PLAN_H
#define HEF_BAND_PLAN_H

#include <stdint.h>
#include <string.h>

#include "hefestos_pins.h"

struct HefBandProfile {
    const char* name;
    const char* region;
    uint32_t    freqMinKHz;
    uint32_t    freqMaxKHz;
    uint8_t     defaultSf;
    uint16_t    bwKHz;
    uint8_t     crNum;
    int8_t      eirpDbmMax;       // EIRP maximo de referencia
    float       dutyLimitPercent; // orcamento de duty cycle (auto-imposto ou normativo)
    uint32_t    minIntervalMs;    // intervalo minimo entre transmissoes
    const char* note;
};

class HefBandPlan {
public:
    static const uint8_t PROFILE_COUNT = 3;

    static const HefBandProfile* profiles() {
        static const HefBandProfile p[] = {
            {
                "915-ANATEL", "Brasil (ANATEL)",
                915000, 928000,
                8, 125, 4,
                30, 10.0f, 1000UL,
                "Faixa ISM. A ANATEL nao impoe duty cycle geral nesta faixa; "
                "10% e' um orcamento proprio (conservador). O EIRP depende "
                "da modalidade e da sub-faixa - CONFIRMAR com a ANATEL."
            },
            {
                "915-FCC", "EUA (FCC Part 15.247)",
                902000, 928000,
                8, 125, 4,
                30, 10.0f, 1000UL,
                "Part 15.247 nao impoe duty cycle geral, mas exige canal de "
                "50 kHz eiha restrito. 10% e' um orcamento proprio. "
                "Acesso por espectro espalhado - CONFIRMAR com a FCC."
            },
            {
                "868-ETSI", "Europa (ETSI EN 300 220)",
                868000, 870000,
                8, 125, 4,
                14, 1.0f, 30000UL,
                "Duty cycle de 1% (0,1% nas sub-bandas 868.0-868.6 / "
                "868.7-869.2 / 869.4-869.65). EIRP 14 dBm (25 mW). "
                "CONFIRMAR a sub-banda exata antes de operar."
            }
        };
        return p;
    }

    static uint8_t count() {
        return PROFILE_COUNT;
    }

    static const HefBandProfile* byName(const char* name) {
        if (!name) return nullptr;
        const HefBandProfile* p = profiles();
        for (uint8_t i = 0; i < count(); i++) {
            const char* a = p[i].name;
            const char* b = name;
            while (*a && *a == *b) { a++; b++; }
            if (*a == 0 && *b == 0) return &p[i];
        }
        return nullptr;
    }

    // Perfil ativo: o padrao de compilacao (HEF_BAND_PROFILE).
    static const HefBandProfile* active() {
        const HefBandProfile* p = byName(HEF_BAND_PROFILE);
        if (p) return p;
        return &profiles()[0];
    }

    static bool frequencyAllowed(const HefBandProfile& p, uint32_t freqKHz) {
        return freqKHz >= p.freqMinKHz && freqKHz <= p.freqMaxKHz;
    }

    static bool frequencyAllowed(const HefBandProfile* p, uint32_t freqKHz) {
        return p ? frequencyAllowed(*p, freqKHz) : false;
    }

    static bool frequencyAllowed(uint32_t freqKHz) {
        return frequencyAllowed(*active(), freqKHz);
    }
};

#endif // HEF_BAND_PLAN_H
